package org.mozilla.android.sync.test.helpers;

import java.util.concurrent.ExecutorService;

import junit.framework.AssertionFailedError;

import org.mozilla.gecko.sync.repositories.delegates.RepositorySessionWipeDelegate;

public class ExpectSuccessRepositoryWipeDelegate extends ExpectSuccessDelegate
    implements RepositorySessionWipeDelegate {

  public ExpectSuccessRepositoryWipeDelegate(WaitHelper waitHelper) {
    super(waitHelper);
  }

  @Override
  public void onWipeSucceeded() {
    log("Wipe succeeded.");
    performNotify();
  }

  @Override
  public void onWipeFailed(Exception ex) {
    log("Wipe failed.", ex);
    performNotify(new AssertionFailedError("onWipeFailed: wipe should not have failed."));
  }

  @Override
  public RepositorySessionWipeDelegate deferredWipeDelegate(ExecutorService executor) {
    log("Wipe deferred.");
    return this;
  }
}
