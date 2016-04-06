package com.smartcard.pgp.api;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({ 
	com.smartcard.pgp.api.TestAPI.class,
	com.smartcard.pgp.api.TestAPI_AES.class,
})
public class API_Suite {

}
