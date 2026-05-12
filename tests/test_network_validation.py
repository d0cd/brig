"""Tests for brig.network.validation — domain/IP validation."""

import unittest

from brig.network.validation import is_overly_permissive_domain, is_suspicious_domain


class TestIsSuspiciousDomain(unittest.TestCase):
    """Test is_suspicious_domain() detects DNS rebinding risks."""

    def test_wildcard_everything(self):
        self.assertTrue(is_suspicious_domain("*"))

    def test_wildcard_all_domains(self):
        self.assertTrue(is_suspicious_domain("*.*"))

    def test_localhost_variant(self):
        self.assertTrue(is_suspicious_domain("*.localhost"))

    def test_local_network(self):
        self.assertTrue(is_suspicious_domain("*.local"))

    def test_internal_domain(self):
        self.assertTrue(is_suspicious_domain("*.internal"))

    def test_lan_domain(self):
        self.assertTrue(is_suspicious_domain("*.lan"))

    def test_private_domain(self):
        self.assertTrue(is_suspicious_domain("*.private"))

    def test_home_domain(self):
        self.assertTrue(is_suspicious_domain("*.home"))

    def test_corp_domain(self):
        self.assertTrue(is_suspicious_domain("*.corp"))

    def test_safe_specific_domain(self):
        self.assertEqual(is_suspicious_domain("api.github.com"), "")

    def test_safe_wildcard_subdomain(self):
        self.assertEqual(is_suspicious_domain("*.github.com"), "")

    def test_case_insensitive(self):
        self.assertTrue(is_suspicious_domain("*.LOCAL"))

    def test_bare_tld_wildcard(self):
        """Wildcard on bare TLD like *.xyz (one dot) is suspicious."""
        self.assertTrue(is_suspicious_domain("*.xyz"))


class TestIsOverlyPermissiveDomain(unittest.TestCase):
    """Test is_overly_permissive_domain() warns on broad TLD patterns."""

    def test_wildcard_com(self):
        self.assertTrue(is_overly_permissive_domain("*.com"))

    def test_wildcard_net(self):
        self.assertTrue(is_overly_permissive_domain("*.net"))

    def test_wildcard_org(self):
        self.assertTrue(is_overly_permissive_domain("*.org"))

    def test_wildcard_io(self):
        self.assertTrue(is_overly_permissive_domain("*.io"))

    def test_safe_specific(self):
        self.assertEqual(is_overly_permissive_domain("*.example.com"), "")

    def test_short_tld_warning(self):
        """Short TLDs like *.de get a warning even if not in the list."""
        warning = is_overly_permissive_domain("*.de")
        self.assertTrue(warning)

    def test_long_tld_no_warning(self):
        """TLDs longer than 4 chars and not in the list are fine."""
        self.assertEqual(is_overly_permissive_domain("*.museum"), "")
