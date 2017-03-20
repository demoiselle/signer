package org.demoiselle.signer.agent.desktop;

public class SplashScreenThread extends Thread {

	public void run() {
		new SplashScreen(5000);
	}

}
