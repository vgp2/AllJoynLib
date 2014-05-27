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

import java.security.PublicKey;

/**
 * Class representing the identity of a peer
 * @author Philemon von Bergen
 *
 */
public class Identity {

	private String name;
	private PublicKey publicKey;

	/**
	 * Create an Identity object
	 * @param name well-known name of the peer
	 * @param publicKey public key corresponding to the private used by this peer to sign its messages
	 */
	public Identity(String name, PublicKey publicKey){
		this.name = name;
		this.publicKey = publicKey;
	}

	/**
	 * Get the well-known name of the peer
	 * @return the well-known name of the peer
	 */
	public String getName() {
		return name;
	}

	/**
	 * Set the well-known name of the peer
	 * @param name the well-known name of the peer
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Get the public key corresponding to the private used by this peer to sign its messages
	 * @return the public key corresponding to the private used by this peer to sign its messages
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Set the public key corresponding to the private used by this peer to sign its messages
	 * @param publicKey the public key corresponding to the private used by this peer to sign its messages
	 */
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result
				+ ((publicKey == null) ? 0 : publicKey.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Identity other = (Identity) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		if (publicKey == null) {
			if (other.publicKey != null)
				return false;
		} else if (!publicKey.equals(other.publicKey))
			return false;
		return true;
	}

}
