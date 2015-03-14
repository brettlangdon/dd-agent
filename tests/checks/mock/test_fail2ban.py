# stdlib
import unittest
import subprocess

# third party
import mock

# project
from tests.checks.common import AgentCheckTest, get_check


class Fail2BanTestCase(unittest.TestCase):
    def setUp(self):
        self.config = """
init_config:

instances:
   - sudo: True
"""

    def _get_check(self):
        check, _ = get_check("fail2ban", self.config)
        return check

    def test_execute_command(self):
        check = self._get_check()
        with mock.patch("subprocess.Popen") as popen:
            popen.return_value = mock.Mock()
            popen.return_value.returncode = 0
            popen.return_value.communicate.return_value = ("Output\nHere", None)
            output = check.execute_command(["some", "args"])
            self.assertEquals(["Output", "Here"], list(output))
            args = list(popen.call_args)
            self.assertTrue(["some", "args"] in args[0])

    def test_execute_command_sudo(self):
        check = self._get_check()
        with mock.patch("subprocess.Popen") as popen:
            popen.return_value = mock.Mock()
            popen.return_value.returncode = 0
            popen.return_value.communicate.return_value = ("Output\nHere", None)
            output = check.execute_command(["some", "args"], sudo=True)
            self.assertEquals(["Output", "Here"], list(output))
            args = list(popen.call_args)
            self.assertTrue(["sudo", "some", "args"] in args[0])

    def test_get_jails(self):
        check = self._get_check()
        with mock.patch.object(check, "execute_command") as execute_command:
            execute_command.return_value = [
                "Status",
                "|- Number of jail:\t2"
                "`- Jail list:\tssh, ssh-ddos"
            ]

            self.assertEquals(["ssh", "ssh-ddos"], list(check.get_jails()))
            self.assertEquals(["ssh"], list(check.get_jails(jail_blacklist=["ssh-ddos"])))
            self.assertEquals([], list(check.get_jails(jail_blacklist=["ssh-ddos", "ssh"])))

    def test_get_jail_status(self):
        status_output = [
            "Status for the jail: ssh",
            "|- filter",
            "|  |- File list:\t/var/log/auth.log",
            "|  |- Currently failed:\t2",
            "|  `- Total failed:\t62219",
            "`- action",
            "   |- Currently banned:\t2",
            "   |  `- IP list:\t104.217.154.54 222.186.56.43",
            "   `- Total banned:\t4985"
        ]
        expected = {
            "filter": {
                "file_list": "/var/log/auth.log",
                "currently_failed": "2",
                "total_failed": "62219"
            },
            "action": {
                "currently_banned": "2",
                "ip_list": "104.217.154.54 222.186.56.43",
                "total_banned": "4985"
            }
        }
        check = self._get_check()
        with mock.patch.object(check, "execute_command") as execute_command:
            execute_command.return_value = status_output
            status = check.get_jail_status("ssh")
            self.assertEqual(expected, status)

    def test_get_jail_stats(self):
        jails = ["ssh"]
        jail_status = {
            "filter": {
                "file_list": "/var/log/auth.log",
                "currently_failed": "2",
                "total_failed": "62219"
            },
            "action": {
                "currently_banned": "2",
                "ip_list": "104.217.154.54 222.186.56.43",
                "total_banned": "4985"
            }
        }
        exptected = [
            ("ssh", "fail2ban.action.currently_banned", "2"),
            ("ssh", "fail2ban.action.total_banned", "4985"),
            ("ssh", "fail2ban.filter.currently_failed", "2"),
            ("ssh", "fail2ban.filter.total_failed", "62219")
        ]
        check = self._get_check()
        with mock.patch.object(check, "get_jail_status") as get_jail_status:
            with mock.patch.object(check, "get_jails") as get_jails:
                get_jails.return_value = jails
                get_jail_status.return_value = jail_status
                stats = check.get_jail_stats()
                self.assertEquals(exptected, list(stats))

    def test_can_ping_fail2ban_pong(self):
        check = self._get_check()
        with mock.patch.object(check, "execute_command") as execute_command:
            execute_command.return_value = ["Server replied: pong"]
            self.assertTrue(check.can_ping_fail2ban())
            execute_command.assert_called_with(["fail2ban-client", "ping"], sudo=False)

    def test_can_ping_fail2ban_fail(self):
        check = self._get_check()
        with mock.patch.object(check, "execute_command") as execute_command:
            # if it cannot connect we will get a subprocess.CalledProcessError
            # which means execute_command will return []
            execute_command.return_value = []
            self.assertFalse(check.can_ping_fail2ban())
            execute_command.assert_called_with(["fail2ban-client", "ping"], sudo=False)

    def test_check(self):
        jail_stats = [
            ("ssh", "fail2ban.action.currently_banned", "2"),
            ("ssh", "fail2ban.action.total_banned", "4985"),
            ("ssh", "fail2ban.filter.currently_failed", "2"),
            ("ssh", "fail2ban.filter.total_failed", "62219")
        ]

        expected_metrics = [
            ('fail2ban.filter.total_failed', '62219', {'type': 'gauge', 'tags': ['jail:ssh']}),
            ('fail2ban.action.total_banned', '4985', {'type': 'gauge', 'tags': ['jail:ssh']}),
            ('fail2ban.action.currently_banned', '2', {'type': 'gauge', 'tags': ['jail:ssh']}),
            ('fail2ban.filter.currently_failed', '2', {'type': 'gauge', 'tags': ['jail:ssh']})
        ]

        check, instances = get_check("fail2ban", self.config)
        with mock.patch.object(check, "can_ping_fail2ban") as can_ping_fail2ban:
            with mock.patch.object(check, "get_jail_stats") as get_jail_stats:
                can_ping_fail2ban.return_value = True
                get_jail_stats.return_value = jail_stats

                check.check(instances[0])
                self._assert_expected_metrics(expected_metrics, check.get_metrics())

    def _assert_expected_metrics(self, expected, actual):
        for metric, value, tags in expected:
            for actual_metric, _, actual_value, actual_tags in actual:
                if metric == actual_metric and value == actual_value:
                    # copy over the hostname tag, since that is the only missing one
                    tags["hostname"] = actual_tags["hostname"]
                    self.assertEqual(tags, actual_tags)
                    break
            else:
                self.assertFalse(True, "Could not find (%s, %s, %r)" % (metric, value, tags))
