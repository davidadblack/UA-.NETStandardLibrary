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

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Tpm2Lib;

namespace CopyCertToTPM
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                if (string.IsNullOrEmpty(args[0]))
                {
                    throw new ArgumentException("Please provide a .pfx file path!");
                }

                X509Certificate2 certificate = null;
                FileInfo privateKeyFile = new FileInfo(args[0]);
                RSA rsa = null;

                try
                {
                    certificate = new X509Certificate2(
                        privateKeyFile.FullName,
                        string.Empty,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
                    rsa = certificate.GetRSAPrivateKey();
                }
                catch (Exception)
                {
                    certificate = new X509Certificate2(
                        privateKeyFile.FullName,
                        string.Empty,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.DefaultKeySet);
                    rsa = certificate.GetRSAPrivateKey();
                }
                if (rsa != null)
                {
                    int inputBlockSize = rsa.KeySize / 8 - 42;
                    byte[] bytes1 = rsa.Encrypt(new byte[inputBlockSize], RSAEncryptionPadding.OaepSHA1);
                    byte[] bytes2 = rsa.Decrypt(bytes1, RSAEncryptionPadding.OaepSHA1);
                    if (bytes2 == null)
                    {
                        throw new CryptographicException("Certificate's private key cannot be used for encrption/decryption!");
                    }
                }
                else
                {
                    throw new CryptographicException("Certificate's private key not found!");
                }

                Tpm2Device tpmDevice = new TbsDevice();
                Tpm2 tpm;
                AuthValue ownerAuth = new AuthValue();

                tpmDevice.Connect();
                tpm = new Tpm2(tpmDevice);

                // Create a handle based on the hash of the cert thumbprint
                TpmHandle nvHandle = TpmHandle.NV(certificate.Thumbprint.GetHashCode());

                // Clean up the slot
                tpm[ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);

                // Define a slot for the thumbprint
                AuthValue nvAuth = AuthValue.FromRandom(8);
                tpm[ownerAuth].NvDefineSpace(TpmHandle.RhOwner, nvAuth, new NvPublic(nvHandle, TpmAlgId.Sha1, NvAttr.Authread | NvAttr.Authwrite, new byte[0], (ushort)(certificate.RawData.Length + 4)));

                // Write the size of the cert
                tpm[nvAuth].NvWrite(nvHandle, nvHandle, BitConverter.GetBytes(certificate.RawData.Length), 0);

                // Write the cert itself
                tpm[nvAuth].NvWrite(nvHandle, nvHandle, certificate.RawData, 4);

                tpm.Dispose();

                Console.WriteLine("Certificate successfully copied to TPM!");
            }
            catch (Exception e)
            {
                Console.WriteLine("Could not copy certificate to TPM: " + e.Message);
            }
        }
    }
}
