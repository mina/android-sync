/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

package org.mozilla.gecko.sync.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.mozilla.gecko.background.testhelpers.MockSharedPreferences;
import org.mozilla.gecko.sync.CryptoRecord;
import org.mozilla.gecko.sync.ExtendedJSONObject;
import org.mozilla.gecko.sync.MetaGlobal;
import org.mozilla.gecko.sync.NoCollectionKeysSetException;
import org.mozilla.gecko.sync.PersistedMetaGlobal;
import org.mozilla.gecko.sync.crypto.CryptoException;

public class TestPersistedMetaGlobal {
  MockSharedPreferences prefs = null;
  private final String TEST_META_URL = "metaURL";
  private final String TEST_CREDENTIALS = "credentials";

  @Before
  public void setUp() {
    prefs = new MockSharedPreferences();
  }

  @Test
  public void testPersistLastModified() throws CryptoException, NoCollectionKeysSetException {
    long LAST_MODIFIED = System.currentTimeMillis();
    PersistedMetaGlobal persisted = new PersistedMetaGlobal(prefs);

    // Test fresh start.
    assertEquals(-1, persisted.lastModified());

    // Test persisting.
    persisted.persistLastModified(LAST_MODIFIED);
    assertEquals(LAST_MODIFIED, persisted.lastModified());

    // Test clearing.
    persisted.persistLastModified(0);
    assertEquals(-1, persisted.lastModified());
  }

  @Test
  public void testPersistMetaGlobal() throws Exception {
    PersistedMetaGlobal persisted = new PersistedMetaGlobal(prefs);

    // Test fresh start.
    assertNull(persisted.metaGlobal(TEST_META_URL, TEST_CREDENTIALS));

    // Test persisting.
    String body = "{\"id\":\"global\",\"payload\":\"{\\\"syncID\\\":\\\"zPSQTm7WBVWB\\\",\\\"storageVersion\\\":5,\\\"engines\\\":{\\\"clients\\\":{\\\"version\\\":1,\\\"syncID\\\":\\\"fDg0MS5bDtV7\\\"},\\\"bookmarks\\\":{\\\"version\\\":2,\\\"syncID\\\":\\\"NNaQr6_F-9dm\\\"},\\\"forms\\\":{\\\"version\\\":1,\\\"syncID\\\":\\\"GXF29AFprnvc\\\"},\\\"history\\\":{\\\"version\\\":1,\\\"syncID\\\":\\\"av75g4vm-_rp\\\"},\\\"passwords\\\":{\\\"version\\\":1,\\\"syncID\\\":\\\"LT_ACGpuKZ6a\\\"},\\\"prefs\\\":{\\\"version\\\":2,\\\"syncID\\\":\\\"-3nsksP9wSAs\\\"},\\\"tabs\\\":{\\\"version\\\":1,\\\"syncID\\\":\\\"W4H5lOMChkYA\\\"}}}\",\"username\":\"5817483\",\"modified\":1.32046073744E9}";
    MetaGlobal mg = new MetaGlobal(TEST_META_URL, TEST_CREDENTIALS);
    mg.setFromRecord(CryptoRecord.fromJSONRecord(body));
    persisted.persistMetaGlobal(mg);

    MetaGlobal persistedGlobal = persisted.metaGlobal(TEST_META_URL, TEST_CREDENTIALS);
    assertNotNull(persistedGlobal);
    assertEquals("zPSQTm7WBVWB", persistedGlobal.getSyncID());
    assertTrue(persistedGlobal.getEngines() instanceof ExtendedJSONObject);
    assertEquals(Long.valueOf(5), persistedGlobal.getStorageVersion());

    // Test clearing.
    persisted.persistMetaGlobal(null);
    assertNull(persisted.metaGlobal(null, null));
  }
}
