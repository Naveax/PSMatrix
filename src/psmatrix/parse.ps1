[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SourcePath,

    [ValidateSet('auto', 'required', 'off')]
    [string] $AnalyzerMode = 'auto'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $SourcePath,
    [ref] $tokens,
    [ref] $parseErrors
)

$items = @()
foreach ($parseError in $parseErrors) {
    $items += [pscustomobject]@{
        message  = [string] $parseError.Message
        error_id = [string] $parseError.ErrorId
        line     = [int] $parseError.Extent.StartLineNumber
        column   = [int] $parseError.Extent.StartColumnNumber
        extent   = [string] $parseError.Extent.Text
    }
}

$commands = @()
$commandNodes = @($ast.FindAll({
    param($node)
    $node.GetType().FullName -eq 'System.Management.Automation.Language.CommandAst'
}, $true))
foreach ($command in $commandNodes) {
    $parameters = @()
    $elements = @()
    foreach ($element in @($command.CommandElements)) {
        $elements += [string] $element.Extent.Text
        if ($element.GetType().FullName -eq 'System.Management.Automation.Language.CommandParameterAst') {
            $parameters += [string] $element.ParameterName
        }
    }
    $commands += [pscustomobject]@{
        name                = [string] $command.GetCommandName()
        invocation_operator = [string] $command.InvocationOperator
        parameters          = @($parameters)
        elements            = @($elements)
        text                = [string] $command.Extent.Text
        line                = [int] $command.Extent.StartLineNumber
        column              = [int] $command.Extent.StartColumnNumber
    }
}

$typeNames = @()
$typeNodes = @($ast.FindAll({
    param($node)
    $name = $node.GetType().FullName
    ($name -eq 'System.Management.Automation.Language.TypeExpressionAst') -or
    ($name -eq 'System.Management.Automation.Language.TypeConstraintAst')
}, $true))
foreach ($typeNode in $typeNodes) {
    if ($null -ne $typeNode.TypeName) {
        $typeNames += [string] $typeNode.TypeName.FullName
    }
}

$memberAccess = @()
$memberNodes = @($ast.FindAll({
    param($node)
    $name = $node.GetType().FullName
    ($name -eq 'System.Management.Automation.Language.MemberExpressionAst') -or
    ($name -eq 'System.Management.Automation.Language.InvokeMemberExpressionAst')
}, $true))
foreach ($memberNode in $memberNodes) {
    $memberAccess += [pscustomobject]@{
        member = [string] $memberNode.Member.Extent.Text
        text   = [string] $memberNode.Extent.Text
        line   = [int] $memberNode.Extent.StartLineNumber
        column = [int] $memberNode.Extent.StartColumnNumber
    }
}

$providerPaths = @()
$stringNodes = @($ast.FindAll({
    param($node)
    $name = $node.GetType().FullName
    ($name -eq 'System.Management.Automation.Language.StringConstantExpressionAst') -or
    ($name -eq 'System.Management.Automation.Language.ExpandableStringExpressionAst')
}, $true))
foreach ($stringNode in $stringNodes) {
    $value = [string] $stringNode.Value
    if (($value -match '^[A-Za-z][A-Za-z0-9_-]*:') -or ($value -match '^\\\\')) {
        $providerPaths += [pscustomobject]@{
            value  = $value
            line   = [int] $stringNode.Extent.StartLineNumber
            column = [int] $stringNode.Extent.StartColumnNumber
        }
    }
}

$usingStatements = @()
$usingNodes = @($ast.FindAll({
    param($node)
    $node.GetType().FullName -eq 'System.Management.Automation.Language.UsingStatementAst'
}, $true))
foreach ($usingNode in $usingNodes) {
    $usingStatements += [pscustomobject]@{
        kind = [string] $usingNode.UsingStatementKind
        name = [string] $usingNode.Name.Value
        text = [string] $usingNode.Extent.Text
        line = [int] $usingNode.Extent.StartLineNumber
    }
}

$requires = @()
foreach ($token in @($tokens)) {
    if (($token.Kind.ToString() -eq 'Comment') -and ([string] $token.Text -match '^\s*#requires\b')) {
        $requires += [pscustomobject]@{
            text = [string] $token.Text
            line = [int] $token.Extent.StartLineNumber
        }
    }
}

$functions = @()
$functionNodes = @($ast.FindAll({
    param($node)
    $node.GetType().FullName -eq 'System.Management.Automation.Language.FunctionDefinitionAst'
}, $true))
foreach ($functionNode in $functionNodes) {
    $functions += [pscustomobject]@{
        name = [string] $functionNode.Name
        line = [int] $functionNode.Extent.StartLineNumber
    }
}

$classes = @()
$classNodes = @($ast.FindAll({
    param($node)
    $node.GetType().FullName -eq 'System.Management.Automation.Language.TypeDefinitionAst'
}, $true))
foreach ($classNode in $classNodes) {
    $classes += [pscustomobject]@{
        name = [string] $classNode.Name
        kind = if ($classNode.IsClass) { 'class' } elseif ($classNode.IsEnum) { 'enum' } else { 'type' }
        line = [int] $classNode.Extent.StartLineNumber
    }
}


$analyzerResult = [ordered]@{
    mode        = $AnalyzerMode
    status      = 'skipped'
    available   = $false
    version     = $null
    diagnostics = @()
    error       = $null
}

if ($AnalyzerMode -ne 'off') {
    try {
        $candidate = Get-Module -ListAvailable -Name 'PSScriptAnalyzer' |
            Sort-Object -Property Version -Descending |
            Select-Object -First 1
        if ($null -eq $candidate) {
            $analyzerResult.status = 'unavailable'
        }
        else {
            Import-Module -Name $candidate.Path -Force -ErrorAction Stop
            $loaded = Get-Module -Name 'PSScriptAnalyzer' |
                Sort-Object -Property Version -Descending |
                Select-Object -First 1
            $analyzerResult.available = $true
            $analyzerResult.version = [string] $loaded.Version
            $rawDiagnostics = @(Invoke-ScriptAnalyzer -Path $SourcePath -ErrorAction Stop)
            $normalizedDiagnostics = @()
            foreach ($diagnostic in $rawDiagnostics) {
                $corrections = @()
                foreach ($correction in @($diagnostic.SuggestedCorrections)) {
                    if ($null -ne $correction) {
                        $corrections += [pscustomobject]@{
                            description = [string] $correction.Description
                            text        = [string] $correction.Text
                            start_line  = [int] $correction.StartLineNumber
                            start_column = [int] $correction.StartColumnNumber
                            end_line    = [int] $correction.EndLineNumber
                            end_column  = [int] $correction.EndColumnNumber
                        }
                    }
                }
                $normalizedDiagnostics += [pscustomobject]@{
                    rule_name            = [string] $diagnostic.RuleName
                    severity             = [string] $diagnostic.Severity
                    message              = [string] $diagnostic.Message
                    script_name          = [string] $diagnostic.ScriptName
                    line                 = [int] $diagnostic.Line
                    column               = [int] $diagnostic.Column
                    extent               = [string] $diagnostic.Extent
                    suppression_id       = [string] $diagnostic.SuppressionID
                    suggested_corrections = @($corrections)
                }
            }
            $analyzerResult.diagnostics = @($normalizedDiagnostics)
            $analyzerResult.status = 'completed'
        }
    }
    catch {
        $analyzerResult.status = 'error'
        $analyzerResult.error = [string] $_.Exception.ToString()
    }
}

$result = [pscustomobject]@{
    schema = 2
    ok     = ($items.Count -eq 0)
    errors = $items
    analyzer = [pscustomobject] $analyzerResult
    analysis = [pscustomobject]@{
        commands         = @($commands)
        type_names       = @($typeNames | Sort-Object -Unique)
        member_access    = @($memberAccess)
        provider_paths   = @($providerPaths)
        using_statements = @($usingStatements)
        requires         = @($requires)
        functions        = @($functions)
        classes          = @($classes)
    }
}

$result | ConvertTo-Json -Compress -Depth 12
