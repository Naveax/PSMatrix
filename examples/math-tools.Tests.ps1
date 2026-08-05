BeforeAll {
    Import-Module -Name $env:PSMATRIX_SOURCE -Force
}

Describe 'Add-Numbers' {
    It 'adds two positive integers' {
        Add-Numbers -Left 2 -Right 3 | Should -Be 5
    }

    It 'preserves negative values' {
        Add-Numbers -Left -4 -Right 1 | Should -Be -3
    }
}
