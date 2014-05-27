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
package ch.bfh.evoting.alljoyn.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.StreamCorruptedException;

import android.util.Base64;

/**
 * Concrete strategy for serialization using Java serialization
 * @author Philemon von Bergen
 *
 */
public class JavaSerialization implements Serialization {

	/**
	 * Serialize the given object with Java serialization
	 * Return string is base64 encoded
	 */
	@Override
	public String serialize(Object o) {
		if(!(o instanceof Serializable)){
			throw new UnsupportedOperationException();
		}
		
		ByteArrayOutputStream out = null;
        try {
        	out = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(out);
			oos.writeObject(o);
			oos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
        String string = new String(Base64.encode(out.toByteArray(),Base64.DEFAULT));

        return string;
	}

	/**
	 * Deserialize the given string base64 encoded
	 * @param s encoded serialized object
	 * @param classType not needed for Java serialization
	 */
	@Override
	public Object deserialize(String s, Class<?> classType) {
		Object o = null;
		try {
			InputStream in =new ByteArrayInputStream(Base64.decode(s,Base64.DEFAULT));
			ObjectInputStream ois = new ObjectInputStream(in);
			o = ois.readObject();
			ois.close();
		} catch (StreamCorruptedException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		return o;
	}

}
