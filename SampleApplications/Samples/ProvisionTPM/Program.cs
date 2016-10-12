/* Copyright (c) 1996-2016, OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Text;
using Tpm2Lib;

namespace ProvisionTPM
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                // Keypair Generator
                RsaKeyPairGenerator kpGenerator = new RsaKeyPairGenerator();
                kpGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));

                // Create a keypair
                AsymmetricCipherKeyPair keys = kpGenerator.GenerateKeyPair();

                // Init TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                Tpm2 tpm = new Tpm2(tpmDevice);
                AuthValue ownerAuth = new AuthValue();

                // Create a handle based on the hash of the cert thumbprint
                ushort hashcode = (ushort) keys.GetHashCode();
                TpmHandle nvHandle = TpmHandle.NV(hashcode);

                // Clean up the slot
                tpm[ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);

                // Export keys
                TextWriter textWriter = new StringWriter();
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(keys);
                pemWriter.Writer.Flush();
                byte[] rawData = Encoding.ASCII.GetBytes(textWriter.ToString().ToCharArray());
                ushort size = (ushort) (rawData.Length + 4 + 64);
               
                // Define a slot for the keys
                tpm[ownerAuth].NvDefineSpace(TpmHandle.RhOwner, ownerAuth, new NvPublic(nvHandle, TpmAlgId.Sha256, NvAttr.Authread | NvAttr.Authwrite, new byte[0], size));

                // Write the size of the keys
                ushort offset = 0;
                tpm[ownerAuth].NvWrite(nvHandle, nvHandle, BitConverter.GetBytes(rawData.Length), offset);
                offset += 4;

                // Write the keys themselves
                byte[] dataToWrite = new byte[64];
                int index = 0;
                while (index < rawData.Length)
                {
                    for (int i = 0; i < 64; i++)
                    {
                        if (index < rawData.Length)
                        {
                            dataToWrite[i] = rawData[index];
                            index++;
                        }
                        else
                        {
                            dataToWrite[i] = 0;
                        }
                    }
                    tpm[ownerAuth].NvWrite(nvHandle, nvHandle, dataToWrite, offset);
                    offset += 64;
                }

                tpm.Dispose();

                Console.WriteLine("Keys successfully generated and copied to TPM. Hashcode=" + hashcode.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Could not generate or copy keys to TPM: " + e.Message);
            }
        }
    }
}
