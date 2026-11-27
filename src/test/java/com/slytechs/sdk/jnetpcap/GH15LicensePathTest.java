/*
 * Copyright 2026 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.jnetpcap;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.slytechs.sdk.common.license.KeyResolver;
import com.slytechs.sdk.common.license.ProductConfig;
import com.slytechs.sdk.jnetpcap.constant.PcapDlt;

/**
 * Regression coverage for GitHub issue #15: a doubled Windows license path
 * ({@code InvalidPathException}) escaped the Pcap constructor and broke every
 * open.
 *
 * <p>
 * Related issue: https://github.com/slytechs-repos/jnetpcap-sdk/issues/15
 * </p>
 */
@Tag("bugfix")
@Tag("gh-15")
class GH15LicensePathTest extends AbstractTestBase {

	/** The home directory from the original Windows report. */
	private static final String WINDOWS_HOME = "C:\\Users\\67343";

	private static final String[] LICENSE_PROPERTIES = {
			"jnetpcap.license.key",
			"jnetpcap.license.dir",
			"jnetpcap.lic.license.key",
			"jnetpcap.lic.license.dir",
			"license.key",
			"license.dir"
	};

	@TempDir
	Path tempHome;

	@AfterEach
	void clearLicenseOverride() {
		Pcap.licenseKeyOverride = null;
	}

	/**
	 * The path handed to {@code KeyResolver} contains the home directory once and
	 * the file name {@code jnetpcap.lic}. A Windows-style drive path is simulated
	 * here so the assertion does not depend on the host OS: the 3.0.0 shape
	 * ({@code home\home\jnetpcap.lic.lic}) is the one that threw
	 * {@code InvalidPathException} at index 16.
	 */
	@Test
	void licensePathHasSingleHomeSegmentAndJnetpcapLicName() {
		ProductConfig cfg = Pcap.licenseProductConfig();
		String fileName = cfg.fsName + ".lic";

		assertEquals("jnetpcap", cfg.fsName);
		assertEquals("jnetpcap.lic", fileName);
		assertNotNull(cfg.homeDir);
		assertFalse(cfg.homeDir.indexOf(':') >= 0, "homeDir must stay relative on Windows");
		assertFalse(cfg.homeDir.startsWith("\\") || cfg.homeDir.startsWith("/"));

		String joined = windowsJoin(WINDOWS_HOME, cfg.homeDir, fileName);
		assertEquals(WINDOWS_HOME + "\\.jnetpcap\\jnetpcap.lic", joined);
		assertEquals(1, count(joined, WINDOWS_HOME));
		assertTrue(joined.endsWith("\\jnetpcap.lic"));
		assertFalse(joined.contains("jnetpcap.lic.lic"));
		assertDoesNotThrow(() -> windowsPathOf(WINDOWS_HOME, cfg.homeDir, fileName));

		// Same join the host JDK performs. On Linux ':' is legal, so also count.
		Path hostPath = Path.of(WINDOWS_HOME, cfg.homeDir, fileName);
		String rendered = hostPath.toString().replace('/', '\\');
		assertEquals("jnetpcap.lic", hostPath.getFileName().toString());
		assertEquals(1, count(rendered, WINDOWS_HOME));
		assertFalse(rendered.contains("jnetpcap.lic.lic"));

		// The reported 3.0.0 path is illegal under Windows rules.
		InvalidPathException doubled = assertThrows(InvalidPathException.class,
				() -> windowsPathOf(WINDOWS_HOME, WINDOWS_HOME, "jnetpcap.lic.lic"));
		assertEquals(16, doubled.getIndex());
		assertTrue(doubled.getInput().endsWith("jnetpcap.lic.lic"));
		assertEquals(2, count(doubled.getInput(), WINDOWS_HOME));
	}

	/**
	 * sdk-common reads {@code Path.of(user.home, homeDir, fsName + ".lic")}. With
	 * the corrected config that file is found, and a decoy at the doubled location
	 * is not.
	 */
	@Test
	void keyResolverReadsSingleHomeLicenseFile() throws Exception {
		assertNoLicenseEnvironment();

		String expected = "SINGLE-HOME-KEY-0123456789";
		String decoy = "DOUBLED-HOME-KEY-0123456789";
		Path licenseFile = tempHome.resolve(".jnetpcap").resolve("jnetpcap.lic");
		Files.createDirectories(licenseFile.getParent());
		Files.writeString(licenseFile, expected);

		Path doubled = Path.of(tempHome.toString(), tempHome.toString(), "jnetpcap.lic.lic");
		Files.createDirectories(doubled.getParent());
		Files.writeString(doubled, decoy);

		Map<String, String> saved = clearLicenseProperties();
		String previousHome = System.setProperty("user.home", tempHome.toString());
		try {
			ProductConfig cfg = Pcap.licenseProductConfig();
			Path resolved = Path.of(System.getProperty("user.home"), cfg.homeDir, cfg.fsName + ".lic");
			assertEquals(licenseFile, resolved);
			assertEquals(1, count(resolved.toString(), tempHome.toString()));
			assertEquals("jnetpcap.lic", resolved.getFileName().toString());

			String found = new KeyResolver().findLicenseKey(cfg);
			assertEquals(expected, found);
			assertNotEquals(decoy, found);
		} finally {
			restoreHome(previousHome);
			restoreProperties(saved);
		}
	}

	@Test
	void jnetpcapLicenseKeyPropertyIsHonored() throws Exception {
		assertNoLicenseEnvironment();

		String key = "PROPERTY-KEY-0123456789ABCD";
		assertTrue(key.length() > 20);

		Map<String, String> saved = clearLicenseProperties();
		String previousHome = System.setProperty("user.home", tempHome.toString());
		try {
			System.setProperty("jnetpcap.license.key", key);

			ProductConfig cfg = Pcap.licenseProductConfig();
			assertEquals("jnetpcap.license.key", cfg.fsName + ".license.key");
			assertEquals(key, new KeyResolver().findLicenseKey(cfg));
			assertEquals(key, Pcap.resolveLicenseKey());
		} finally {
			restoreHome(previousHome);
			restoreProperties(saved);
		}
	}

	@Test
	void legacyLicenseKeyPropertyStillHonored() throws Exception {
		assertNoLicenseEnvironment();

		String key = "LEGACY-KEY-0123456789ABCDEF";
		Map<String, String> saved = clearLicenseProperties();
		String previousHome = System.setProperty("user.home", tempHome.toString());
		try {
			System.setProperty(Pcap.LEGACY_LICENSE_KEY_PROPERTY, key);
			assertNull(System.getProperty("jnetpcap.license.key"));
			assertEquals(key, Pcap.resolveLicenseKey());
		} finally {
			restoreHome(previousHome);
			restoreProperties(saved);
		}
	}

	/**
	 * A {@code RuntimeException} from key resolution is logged and swallowed, and
	 * opening a bundled capture still succeeds with no license key and no license
	 * environment variable.
	 */
	@Test
	@Tag("offline-capture")
	void resolverRuntimeExceptionDoesNotPreventOpenOffline() throws Exception {
		assertNoLicenseEnvironment();
		assertTrue(Pcap0_4.isSupported(), "libpcap was not loaded; cannot open the bundled capture");

		Map<String, String> saved = clearLicenseProperties();

		AtomicBoolean resolverCalled = new AtomicBoolean();
		Pcap.licenseKeyOverride = () -> {
			resolverCalled.set(true);
			throw new InvalidPathException(
					WINDOWS_HOME + "\\" + WINDOWS_HOME + "\\jnetpcap.lic.lic",
					"Illegal char <:>",
					16);
		};

		try (Pcap pcap = Pcap.openOffline(OFFLINE_FILE)) {
			assertTrue(resolverCalled.get(), "constructor gate did not invoke the resolver");
			assertNotNull(pcap.handle());
			assertEquals(PcapDlt.EN10MB, pcap.datalink());
		} finally {
			Pcap.licenseKeyOverride = null;
			restoreProperties(saved);
		}
	}

	private static void assertNoLicenseEnvironment() {
		assertNull(System.getenv("JNETPCAP_LICENSE_KEY"));
		assertNull(System.getenv("JNETPCAP_LICENSE_DIR"));
		assertNull(System.getenv("LICENSE_KEY"));
		assertNull(System.getenv("LICENSE_DIR"));
	}

	private static Map<String, String> clearLicenseProperties() {
		Map<String, String> saved = new HashMap<>();
		for (String name : LICENSE_PROPERTIES) {
			saved.put(name, System.getProperty(name));
			System.clearProperty(name);
		}
		return saved;
	}

	private static void restoreProperties(Map<String, String> saved) {
		for (Map.Entry<String, String> entry : saved.entrySet()) {
			if (entry.getValue() == null)
				System.clearProperty(entry.getKey());
			else
				System.setProperty(entry.getKey(), entry.getValue());
		}
	}

	private static void restoreHome(String previousHome) {
		if (previousHome == null)
			System.clearProperty("user.home");
		else
			System.setProperty("user.home", previousHome);
	}

	/**
	 * Joins path elements the way {@code Path.of} does on Windows, then applies
	 * the Windows rule that {@code ':'} is legal only as the drive separator.
	 */
	private static String windowsJoin(String first, String... more) {
		StringBuilder joined = new StringBuilder(first);
		for (String part : more) {
			if (part == null || part.isEmpty())
				continue;
			if (joined.length() > 0 && joined.charAt(joined.length() - 1) != '\\')
				joined.append('\\');
			joined.append(part);
		}
		return joined.toString();
	}

	private static void windowsPathOf(String first, String... more) {
		String path = windowsJoin(first, more);
		for (int i = 0; i < path.length(); i++) {
			if (path.charAt(i) == ':' && i != 1)
				throw new InvalidPathException(path, "Illegal char <:>", i);
		}
	}

	private static int count(String text, String needle) {
		int count = 0;
		for (int from = 0; from <= text.length() - needle.length();) {
			int at = text.indexOf(needle, from);
			if (at < 0)
				break;
			count++;
			from = at + needle.length();
		}
		return count;
	}
}
