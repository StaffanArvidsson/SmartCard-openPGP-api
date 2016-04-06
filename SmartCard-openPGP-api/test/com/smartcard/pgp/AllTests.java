package com.smartcard.pgp;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;


@RunWith(Suite.class)
@SuiteClasses({ 
	com.smartcard.pgp.api.API_Suite.class,
	})
public class AllTests {

}