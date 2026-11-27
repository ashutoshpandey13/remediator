from unittest import TestCase, mock

from remediator.remediation import dockerfile_remediation as dr

ORIGINAL = "FROM node:16\nWORKDIR /app\nCOPY . .\nCMD [\"node\", \"app.js\"]\n"
GOOD = (
    "# Changed from node:16\n"
    "FROM registry.redhat.io/ubi9/nodejs-24-minimal:latest\n"
    "USER 1001\n"
    "WORKDIR /app\n"
    "COPY . .  # copy sources\n"
    "CMD [\"node\", \"app.js\"]\n"
)


class DockerfileFromReplyTest(TestCase):
    def test_bare_dockerfile_gets_ubi_mirror_and_inline_comments_removed(self):
        out = dr._dockerfile_from_reply(GOOD)
        self.assertIn("FROM registry.access.redhat.com/ubi9/nodejs-24-minimal:latest", out)
        self.assertNotIn("registry.redhat.io", out)
        self.assertIn("COPY . .", out)
        self.assertNotIn("copy sources", out)
        # only ARG lines may precede FROM, so the leading comment is dropped
        self.assertTrue(out.startswith("FROM "))

    def test_fenced_dockerfile_with_prose_around_it(self):
        reply = f"Here is the fixed file:\n```dockerfile\n{GOOD}```\nThis removes the EOL base image."
        out = dr._dockerfile_from_reply(reply)
        self.assertIn("FROM registry.access.redhat.com/ubi9", out)
        self.assertNotIn("Here is", out)
        self.assertNotIn("This removes", out)
        self.assertNotIn("```", out)

    def test_the_fence_that_holds_the_dockerfile_is_used_not_the_first_fence(self):
        reply = f"Build it with:\n```bash\ndocker build -t app .\n```\nDockerfile:\n```\n{GOOD}```\n"
        out = dr._dockerfile_from_reply(reply)
        self.assertTrue(out.startswith("FROM registry.access.redhat.com/ubi9"))
        self.assertNotIn("docker build", out)

    def test_unfenced_prose_before_from_is_dropped(self):
        out = dr._dockerfile_from_reply("Sure! The updated Dockerfile:\n\nFROM ubi9/ubi-minimal\nRUN true\n")
        self.assertTrue(out.startswith("FROM ubi9/ubi-minimal"))
        self.assertNotIn("Sure", out)

    def test_arg_before_from_is_kept(self):
        out = dr._dockerfile_from_reply("ARG V=1\nFROM base:${V}\nRUN true\n")
        self.assertTrue(out.startswith("ARG V=1\nFROM base:${V}"))

    def test_reply_without_from_is_rejected_with_a_short_snippet(self):
        for reply in ("", "registry.access.redhat.com/ubi9/nodejs-24-minimal:latest",
                      "Which base image would you like me to use?"):
            with self.subTest(reply=reply):
                with self.assertRaises(ValueError) as ctx:
                    dr._dockerfile_from_reply(reply)
                self.assertIn("no FROM instruction", str(ctx.exception))
        long_reply = "x" * 5000
        with self.assertRaises(ValueError) as ctx:
            dr._dockerfile_from_reply(long_reply)
        self.assertLess(len(str(ctx.exception)), 400)


class GenerateDockerfileRemediationTest(TestCase):
    def test_valid_first_reply_calls_bob_once(self):
        with mock.patch.object(dr, "call_bob", return_value=GOOD) as bob:
            out = dr.generate_dockerfile_remediation(ORIGINAL, [{"id": "CVE-1"}])
        self.assertEqual(bob.call_count, 1)
        self.assertIn("FROM registry.access.redhat.com/ubi9/nodejs-24-minimal:latest", out)

    def test_bad_first_reply_is_retried_once_with_a_stricter_prompt(self):
        with mock.patch.object(dr, "call_bob",
                               side_effect=["Do you want Node 22 or 24?", GOOD]) as bob:
            with self.assertLogs(dr.logger, level="WARNING"):
                out = dr.generate_dockerfile_remediation(ORIGINAL, [{"id": "CVE-1"}])
        self.assertEqual(bob.call_count, 2)
        self.assertIn("did not contain a Dockerfile", bob.call_args_list[1][0][0])
        self.assertIn("FROM registry.access.redhat.com", out)

    def test_two_bad_replies_raise_instead_of_returning_garbage(self):
        with mock.patch.object(dr, "call_bob", return_value="no dockerfile here") as bob:
            with self.assertLogs(dr.logger, level="WARNING"):
                with self.assertRaises(ValueError):
                    dr.generate_dockerfile_remediation(ORIGINAL, [])
        self.assertEqual(bob.call_count, 2)

    def test_bob_errors_are_not_retried(self):
        with mock.patch.object(dr, "call_bob", side_effect=Exception("bob run failed")) as bob:
            with self.assertRaises(Exception):
                dr.generate_dockerfile_remediation(ORIGINAL, [])
        self.assertEqual(bob.call_count, 1)
