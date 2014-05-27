/* 
 * MobiVote
 * 
 *  MobiVote: Mobile application for boardroom voting
 *  Copyright (C) 2014 Bern
 *  University of Applied Sciences (BFH), Research Institute for Security
 *  in the Information Society (RISIS), E-Voting Group (EVG) Quellgasse 21,
 *  CH-2501 Biel, Switzerland
 * 
 *  Licensed under Dual License consisting of:
 *  1. GNU Affero General Public License (AGPL) v3
 *  and
 *  2. Commercial license
 * 
 *
 *  1. This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 *
 *  2. Licensees holding valid commercial licenses for MobiVote may use this file in
 *   accordance with the commercial license agreement provided with the
 *   Software or, alternatively, in accordance with the terms contained in
 *   a written agreement between you and Bern University of Applied Sciences (BFH), 
 *   Research Institute for Security in the Information Society (RISIS), E-Voting Group (EVG)
 *   Quellgasse 21, CH-2501 Biel, Switzerland.
 * 
 *
 *   For further information contact us: http://e-voting.bfh.ch/
 * 
 *
 * Redistributions of files must retain the above copyright notice.
 */
package ch.bfh.evoting.alljoyn;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import android.util.Base64;
import android.util.Log;

/**
 * Class used to sign and verify messages' signature
 * @author Philemon von Bergen
 *
 */
public class MessageAuthenticater {

	private static final String TAG = MessageAuthenticater.class.getSimpleName();

	private PublicKey publicKey;
	private PrivateKey privateKey;

	/**
	 * Generate a key pair used to sign messages' content and verify signatures
	 * We limit the size of these RSA keys to 512 bits. The reason is that we want to generate
	 * a new key pair each time the application is launched, in order not to have to save it.
	 * In our case, 512 bits is enough since the keys are not used longer than one our, what is to less 
	 * to make a bruteforce attack.
	 */
	public void generateKeys(){
		try {
			KeyPairGenerator generator;
			generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(512, new SecureRandom());
			KeyPair pair = generator.generateKeyPair();
			publicKey = pair.getPublic();
			privateKey = pair.getPrivate();  

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} 
	}

	/**
	 * Decode a Base64 encoded public key in a PublicKey object
	 * @param encodedKey the Base64 encoded key
	 * @return the PublicKey object
	 */
	public PublicKey decodePublicKey(String encodedKey){
		byte[] keyBytes = Base64.decode(encodedKey, Base64.DEFAULT);

		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFact = null;
		PublicKey pubKey = null;
		try {
			keyFact = KeyFactory.getInstance("RSA", "BC");
			pubKey = keyFact.generatePublic(x509KeySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			Log.e(TAG,e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			Log.e(TAG,e.getMessage());
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			Log.e(TAG,e.getMessage());
		}
		return pubKey;
	}

	/**
	 * Sign the given content
	 * @param valueToSign content to sign
	 * @return the byte array composing the signature
	 */
	public byte[] sign(byte[] valueToSign) {
		//sign message
		Signature instance;
		byte[] signature;
		try {
			instance = Signature.getInstance("SHA1withRSA", "BC");

			instance.initSign(privateKey);
			instance.update(valueToSign);
			signature = instance.sign();
		} catch (NoSuchAlgorithmException e1) {
			Log.e(TAG, "Unable to send message because signature failed");
			e1.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			Log.e(TAG, "Unable to send message because signature failed");
			e.printStackTrace();
			return null;
		} catch (SignatureException e) {
			Log.e(TAG, "Unable to send message because signature failed");
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			Log.e(TAG, "Unable to send message because signature failed");
			e.printStackTrace();
			return null;
		}

		return signature;

	}

	/**
	 * Verify a signature
	 * @param publicKey the public key corresponding to the private key used to generated the signature
	 * @param signature the signature
	 * @param message the message's content that was signed
	 * @return whether the signature is correct or not
	 */
	public boolean verifySignature(PublicKey publicKey, byte[] signature, byte[] message) {
		Signature instance;

		try {
			instance = Signature.getInstance("SHA1withRSA", "BC");

			instance.initVerify(publicKey);
			instance.update(message);
			return instance.verify(signature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			Log.e(TAG, e.getMessage());
			return false;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			Log.e(TAG, e.getMessage());
			return false;
		} catch (SignatureException e) {
			e.printStackTrace();
			Log.e(TAG, e.getMessage());
			return false;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			Log.e(TAG, e.getMessage());
			return false;
		}

	}

	/**
	 * Get the generated public key
	 * @return the generated public key
	 */
	public PublicKey getMyPublicKey(){
		return this.publicKey;
	}

}
