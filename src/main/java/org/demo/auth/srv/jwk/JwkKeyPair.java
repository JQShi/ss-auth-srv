package org.demo.auth.srv.jwk;

public class JwkKeyPair {

	private String id;

	private String privateKey;

	private String publicKey;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	@Override
	public String toString() {
		return "JwkKeyPair [id=" + id + ", privateKey=" + privateKey + ", publicKey=" + publicKey + "]";
	}

}
