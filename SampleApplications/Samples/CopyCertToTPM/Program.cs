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
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
                    throw new ArgumentException("Please provide a certificate file path!");
                }

                X509Certificate2 certificate = null;
                FileInfo certFile = new FileInfo(args[0]);
                RSA rsa = null;

                try
                {
                    certificate = new X509Certificate2(
                        certFile.FullName,
                        string.Empty,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
                    rsa = certificate.GetRSAPrivateKey();
                }
                catch (Exception)
                {
                    certificate = new X509Certificate2(
                        certFile.FullName,
                        string.Empty,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.DefaultKeySet);
                    rsa = certificate.GetRSAPrivateKey();
                }
                if (certificate.HasPrivateKey)
                {
                if (rsa != null)
                {
                    int inputBlockSize = rsa.KeySize / 8 - 42;
                    byte[] bytes1 = rsa.Encrypt(new byte[inputBlockSize], RSAEncryptionPadding.OaepSHA1);
                    byte[] bytes2 = rsa.Decrypt(bytes1, RSAEncryptionPadding.OaepSHA1);
                    if (bytes2 == null)
                    {
                            throw new CryptographicException("Certificate's private key cannot be used for encryption/decryption!");
                    }
                }
                else
                {
                        throw new CryptographicException("Certificate's private could not be retrieved!");
                    }
                }

                Tpm2Device tpmDevice = new TbsDevice();

                tpmDevice.Connect();
                Tpm2 tpm = new Tpm2(tpmDevice);

                AuthValue ownerAuth = new AuthValue();
                AuthValue nvAuth = AuthValue.FromRandom(8);

                // Create a handle based on the hash of the cert thumbprint
                ushort slotIndex = (ushort) certificate.Thumbprint.GetHashCode();
                TpmHandle nvHandle = TpmHandle.NV(slotIndex);

                // Clean up the slot
                tpm[ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);

                ushort size = 0;
                if (certificate.HasPrivateKey)
                {
                    size = (ushort) (certificate.RawData.Length + 4 + 64);
                }
                else
                {
                // Define a slot for the thumbprint
                    size = (ushort) certificate.Thumbprint.ToCharArray().Length;
                }
                tpm[ownerAuth].NvDefineSpace(TpmHandle.RhOwner, nvAuth, new NvPublic(nvHandle, TpmAlgId.Sha1, NvAttr.Authread | NvAttr.Authwrite, new byte[0], size));

                if (certificate.HasPrivateKey)
                {
                // Write the size of the cert
                ushort offset = 0;
                tpm[nvAuth].NvWrite(nvHandle, nvHandle, BitConverter.GetBytes(certificate.RawData.Length), offset);
                offset += 4;

                // Write the cert itself
                byte[] dataToWrite = new byte[64];
                int index = 0;
                while (index < certificate.RawData.Length)
                {
                    for (int i = 0; i < 64; i++)
                    {
                        if (index < certificate.RawData.Length)
                        {
                            dataToWrite[i] = certificate.RawData[index];
                            index++;
                        }
                        else
                        {
                            dataToWrite[i] = 0;
                        }
                    }
                    tpm[nvAuth].NvWrite(nvHandle, nvHandle, dataToWrite, offset);
                    offset += 64;
                    }
                }
                else
                {
                    tpm[nvAuth].NvWrite(nvHandle, nvHandle, Encoding.UTF8.GetBytes(certificate.Thumbprint.ToCharArray()), 0);
                }

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
