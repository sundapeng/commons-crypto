/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.bench;

/*
 *
 * JMH is a Java harness for building, running, and analysing nano/micro/milli/macro
 * benchmarks written in Java and other languages targetting the JVM.
 * http://openjdk.java.net/projects/code-tools/jmh/
 *
 * ============================== HOW TO RUN THIS TEST: ====================================
 * You can run this test with:
 *
 *
 */

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.CipherTransformation;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.cipher.JceCipher;
import org.apache.commons.crypto.cipher.OpensslCipher;
import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.jna.OpensslJnaCipher;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.random.CryptoRandomFactory;
import org.openjdk.jmh.annotations.GenerateMicroBenchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class AESPerfTestWithJMH {
  private static CryptoRandom rand;
   static {
    try {
      rand = CryptoRandomFactory.getCryptoRandom(new Properties());
    } catch (GeneralSecurityException e) {
    }
  }
   private static CipherTransformation[] transformations =
      {CipherTransformation.AES_CBC_NOPADDING, CipherTransformation
          .AES_CBC_PKCS5PADDING,CipherTransformation.AES_CTR_NOPADDING};
  private static Map<String, CipherTransformation[]> cipherModes =
      new HashMap<String, CipherTransformation[]>();

  static {
    cipherModes.put(JceCipher.class.getName(), transformations);
    cipherModes.put(OpensslCipher.class.getName(), transformations);
    cipherModes.put(OpensslJnaCipher.class.getName(), transformations);
  }

  /*command line parameter set
   *
   * usage: -p buffer_size=xxx(default 128)
   *        -p sizeUnit=xx(default KB)
   *        -p cipherClass=xxx(default SunJCE)
   *        -p mode=xxx(default AES/CTR/NoPadding)
   *        -p directBuffer=xxx(default false)
   */

  @Param(value = "128")
  public int buffer_size;
  @Param(value = "KB")
  public String sizeUnit;
  @Param(value = "JceCipher")
  public String cipherClass;
  @Param(value = "AES/CTR/NoPadding")
  public String mode;
  @Param(value = "false")
  public boolean directBuffer = false;

  private CipherTransformation transformation = null;
  private Properties props = null;
  private String className = null;
  
  //byteArray encryption/decryption
  private byte[] inputByteArray;
  private byte[] encByteArray;
  private byte[] tmpByteArray;
  //byteArray for first encrypt and then used for decryption
  private byte[] decByteArray;

  //byteBuffer encryption/decryption
  private ByteBuffer inputByteBuffer;
  private ByteBuffer encByteBuffer;
  private ByteBuffer tmpByteBuffer;
  //byteBuffer for first encrypt and then used for decryption
  private ByteBuffer decByteBuffer;

  private CryptoCipher enc;
  private CryptoCipher dec;
  private byte[] key = new byte[32];
  private byte[] iv = new byte[16];

  /*
   * 1.checkout the input argument. es: buffer_size, sizeUnit, provider and mode.
   *   usage: -p privoder=DC -p buffer_size = 1024 -p sizeUnit=KB -p mode = AES/CTR/NoPadding
   *
   * 2.initialize the encryption and decryption cipher and alloc memory space for encrypt and decrypt result
   *
   */
  @Setup
  public void setup() throws Exception {
    checkArgument();
    System.out.println("Initialising test data : [INPUT_BUFFER_SIZE = " + String
        .format("%d", buffer_size) + sizeUnit + "]");
    initialize();
  }

  private void checkArgument() {
    for (String fullName : cipherModes.keySet()) {
      System.out.println("fullName:" + fullName +" cipherClass:" + cipherClass);
      if (fullName.contains(cipherClass)) {
        className = fullName;
      }
    }
    if (className == null) {
      throw new IllegalArgumentException(
          "the provider parameter is not correct set. the value must be " + cipherModes
              .keySet());
    }
    props = new Properties();
    props.setProperty(ConfigurationKeys.COMMONS_CRYPTO_CIPHER_CLASSES_KEY,
        className);
    for (CipherTransformation t : cipherModes.get(className)) {
      if (t.getName().equals(mode)) {
        transformation = t;
      }
    }
    if (transformation == null) {
      throw new IllegalArgumentException(
          "the mode parameter is not correct set. the value must be " + Arrays
              .asList(cipherModes.get(className)));
    }
    if (!sizeUnit.equals("KB") && !sizeUnit.equals("B")) {
      throw new IllegalArgumentException("sizeUnit parameter must be KB or B");
    }
  }

  private void initialize() throws Exception {

    rand.nextBytes(key);
    rand.nextBytes(iv);

    //intialize for the test data
    final int INPUT_BUFFER_SIZE =
        (sizeUnit.equals("KB") ? 1024 * buffer_size : buffer_size);
    inputByteArray = new byte[INPUT_BUFFER_SIZE];
    rand.nextBytes(inputByteArray);

    //calc the memory space for encryption/decryption according to the cipher mode
    int encryptResultSize = INPUT_BUFFER_SIZE;
    int decryptResultSize = INPUT_BUFFER_SIZE;
    if (!mode.contains("NoPadding")) {
      encryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16) + 2;
      decryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16) + 2;
    } else if (mode.contains("GCM")) {
      encryptResultSize = INPUT_BUFFER_SIZE + 16;
      decryptResultSize = INPUT_BUFFER_SIZE;
    }

    //initialize the cipher for encrypt or decrypt
    try {
      enc = CryptoCipherFactory.getInstance(this.transformation, this.props);
      dec = CryptoCipherFactory.getInstance(this.transformation, this.props);
      AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
      enc.init(CryptoCipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
          paramSpec);
      dec.init(CryptoCipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
          paramSpec);
    } catch (Exception e) {
      throw new RuntimeException("AES failed initialisation - " + e.toString(),
          e);
    }

    //check whether use ByteArray or ByteBuffer
    if (directBuffer) {
      inputByteBuffer = ByteBuffer.allocateDirect(INPUT_BUFFER_SIZE);
      inputByteBuffer.put(inputByteArray);
      inputByteBuffer.flip();
      encByteBuffer = ByteBuffer.allocateDirect(encryptResultSize);
      decByteBuffer = ByteBuffer.allocateDirect(decryptResultSize);
      tmpByteBuffer = ByteBuffer.allocateDirect(encryptResultSize);

      //encrypt the data for decrypt performance test
      enc.doFinal(inputByteBuffer, tmpByteBuffer);
      inputByteBuffer.flip();
      tmpByteBuffer.flip();
      tmpByteBuffer.limit(tmpByteBuffer.capacity());
    } else {
      encByteArray = new byte[encryptResultSize];
      decByteArray = new byte[decryptResultSize];
      tmpByteArray = new byte[encryptResultSize];

      //encrypt the data for decrypt performance test
      enc.doFinal(inputByteArray, 0, inputByteArray.length, tmpByteArray,0);
    }

    enc.close();
    System.out.println("======");
    System.out.println("Testing " + enc.getTransformation().getName() + " " +
        enc.getTransformation()
            .getAlgorithmBlockSize() * 8 + " " + "cipherClass:" + cipherClass + " mode:" +
        mode + (directBuffer ? " directBuffer" : " ByteArray"));
  }

  private void testCipher(CryptoCipher cipher, byte[] input, byte[] output) throws
      ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    cipher.doFinal(input, 0, input.length, output, 0);
  }

  private void testCipher(CryptoCipher cipher, ByteBuffer input,
                          ByteBuffer output) throws ShortBufferException,
      IllegalBlockSizeException, BadPaddingException {
    cipher.doFinal(input, output);
  }

  @GenerateMicroBenchmark
  public void encryptPerfTest() throws Exception {
    //initialize the cipher for encrypt or decrypt
    try {
      enc = CryptoCipherFactory.getInstance(this.transformation, this.props);
      AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
      enc.init(CryptoCipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
          paramSpec);
    } catch (Exception e) {
      throw new RuntimeException("AES failed initialisation - " + e.toString(),
          e);
    }
    if (directBuffer) {
      /*
       * using bytebuffer need reset the input and output bytebuffer
       */
      testCipher(enc, inputByteBuffer, encByteBuffer);
      inputByteBuffer.flip();
      inputByteBuffer.limit(inputByteBuffer.capacity());
      encByteBuffer.flip();
      encByteBuffer.limit(encByteBuffer.capacity());
    } else {
      testCipher(enc, inputByteArray, encByteArray);
    }
    enc.close();
  }

  @GenerateMicroBenchmark
  public void decryptPerfTest() throws Exception {
    //initialize the cipher for encrypt or decrypt
    try {
      dec = CryptoCipherFactory.getInstance(this.transformation, this.props);
      AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
      dec.init(CryptoCipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
          paramSpec);
    } catch (Exception e) {
      throw new RuntimeException("AES failed initialisation - " + e.toString(),
          e);
    }
    if (directBuffer) {
      testCipher(dec, tmpByteBuffer, decByteBuffer);
      tmpByteBuffer.flip();
      tmpByteBuffer.limit(tmpByteBuffer.capacity());
      decByteBuffer.flip();
      decByteBuffer.limit(decByteBuffer.capacity());
    } else {
      testCipher(dec, tmpByteArray, decByteArray);
    }
    dec.close();
  }
}
