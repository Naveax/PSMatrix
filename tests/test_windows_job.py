import unittest
from types import SimpleNamespace

from psmatrix.windows_job import WindowsJob, WindowsJobError, resume_suspended_process


class FakeApi:
    def __init__(self):
        self.created = 101
        self.assigned = []
        self.terminated = []
        self.closed = []
        self.counts = [0]
        self.pids = [301, 302]
        self.working_sets = {301: 4096, 302: 8192}
        self.sampled = []
        self.thread_ids = [202]
        self.resumed = []
        self.resume_result = 1

    def create_job(self):
        return self.created

    def assign_process(self, job_handle, process_handle):
        self.assigned.append((job_handle, process_handle))

    def terminate_job(self, job_handle, exit_code):
        self.terminated.append((job_handle, exit_code))

    def active_process_count(self, job_handle):
        if len(self.counts) > 1:
            return self.counts.pop(0)
        return self.counts[0]

    def job_process_ids(self, job_handle):
        return list(self.pids)

    def process_working_set_bytes(self, job_handle, process_id):
        self.sampled.append((job_handle, process_id))
        return self.working_sets[process_id]

    def close_handle(self, handle):
        self.closed.append(handle)

    def process_thread_ids(self, process_id):
        return list(self.thread_ids)

    def open_thread(self, thread_id):
        return thread_id + 1000

    def resume_thread(self, thread_handle):
        self.resumed.append(thread_handle)
        return self.resume_result


class WindowsJobTests(unittest.TestCase):
    def test_assign_uses_existing_subprocess_handle(self):
        api = FakeApi()
        job = WindowsJob.create(api=api)
        job.assign_process(SimpleNamespace(_handle=303))
        self.assertEqual(api.assigned, [(101, 303)])
        job.close()

    def test_resource_usage_sums_working_sets_and_uses_job_active_count(self):
        api = FakeApi()
        api.counts = [3]
        job = WindowsJob.create(api=api)
        self.assertEqual(job.resource_usage(), (12_288, 3))
        self.assertEqual(api.sampled, [(101, 301), (101, 302)])
        job.close()

    def test_resource_usage_ignores_process_that_exited_during_sampling(self):
        api = FakeApi()
        api.counts = [1]
        api.working_sets[302] = None
        job = WindowsJob.create(api=api)
        self.assertEqual(job.resource_usage(), (4096, 1))
        job.close()

    def test_resource_usage_rejects_closed_job(self):
        api = FakeApi()
        job = WindowsJob.create(api=api)
        job.close()
        with self.assertRaisesRegex(WindowsJobError, "closed Windows Job Object"):
            job.resource_usage()

    def test_terminate_waits_until_job_is_empty(self):
        api = FakeApi()
        api.counts = [2, 1, 0]
        job = WindowsJob.create(api=api)
        job.terminate_and_wait(exit_code=7, timeout_seconds=1)
        self.assertEqual(api.terminated, [(101, 7)])
        self.assertEqual(api.counts, [0])
        job.close()

    def test_terminate_timeout_fails_closed(self):
        api = FakeApi()
        api.counts = [1]
        job = WindowsJob.create(api=api)
        with self.assertRaisesRegex(WindowsJobError, "still has active processes"):
            job.terminate_and_wait(timeout_seconds=0.01)
        job.close()

    def test_close_is_idempotent(self):
        api = FakeApi()
        job = WindowsJob.create(api=api)
        job.close()
        job.close()
        self.assertEqual(api.closed, [101])

    def test_resume_requires_exactly_one_initial_thread(self):
        api = FakeApi()
        resume_suspended_process(42, api=api)
        self.assertEqual(api.resumed, [1202])
        self.assertIn(1202, api.closed)

    def test_resume_rejects_ambiguous_initial_thread_set(self):
        api = FakeApi()
        api.thread_ids = [202, 203]
        with self.assertRaisesRegex(WindowsJobError, "expected exactly 1"):
            resume_suspended_process(42, api=api)

    def test_resume_rejects_unexpected_suspend_count(self):
        api = FakeApi()
        api.resume_result = 2
        with self.assertRaisesRegex(WindowsJobError, "suspend count was 2"):
            resume_suspended_process(42, api=api)
        self.assertIn(1202, api.closed)


if __name__ == "__main__":
    unittest.main()
