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
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using Tpm2Lib;

namespace Opc.Ua
{
    /// <summary>
    /// Provides access to a simple file based certificate store.
    /// </summary>
    public class TPMCertificateStore : DirectoryCertificateStore
    {
        public new void Open(string location)
        {
            lock (m_lock)
            {
                base.Open(location);
                m_tpmDevice.Connect();
                m_tpm = new Tpm2(m_tpmDevice);
            }
        }

        public new void Close()
        {
            lock (m_lock)
            {
                m_tpm.Dispose();
                base.Close();
            }
        }

        public new Task Add(X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException("certificate");
         
            lock (m_lock)
            {
                // Create a handle based on the hash of the cert thumbprint
                ushort slotIndex = BitConverter.ToUInt16(CryptoLib.HashData(TpmAlgId.Sha256, Encoding.UTF8.GetBytes(certificate.Thumbprint)), 0);
                TpmHandle nvHandle = TpmHandle.NV(slotIndex);

                // Clean up the slot
                m_tpm[m_ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);

                // Define a slot for the thumbprint
                m_tpm[m_ownerAuth].NvDefineSpace(TpmHandle.RhOwner, m_ownerAuth, new NvPublic(nvHandle, TpmAlgId.Sha256, NvAttr.Authread | NvAttr.Authwrite, new byte[0], (ushort) certificate.Thumbprint.ToCharArray().Length));

                // Write the thumbprint
                m_tpm[m_ownerAuth].NvWrite(nvHandle, nvHandle, Encoding.UTF8.GetBytes(certificate.Thumbprint.ToCharArray()), 0);
            }

            return base.Add(certificate);
        }

        public new Task<bool> Delete(string thumbprint)
        {
            lock (m_lock)
            {
                // Create a handle based on the hash of the cert thumbprint
                ushort slotIndex = BitConverter.ToUInt16(CryptoLib.HashData(TpmAlgId.Sha256, Encoding.UTF8.GetBytes(thumbprint)), 0);
                TpmHandle nvHandle = TpmHandle.NV(slotIndex);

                // Delete hash of thumbprint from NV storage
                m_tpm[m_ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);
            }

            return base.Delete(thumbprint);
        }
   
        public new X509Certificate2 LoadPrivateKey(string thumbprint, string subjectName, string password)
        {
            try
            {
                // Create a handle based on the hash of the cert thumbprint
                ushort slotIndex = BitConverter.ToUInt16(CryptoLib.HashData(TpmAlgId.Sha256, Encoding.UTF8.GetBytes(thumbprint)), 0);
                TpmHandle nvHandle = TpmHandle.NV(slotIndex);

                // Read size of cert from NV storage (located in the first 4 bytes)
                byte[] certSizeBlob = m_tpm[m_ownerAuth].NvRead(nvHandle, nvHandle, 4, 0);
                
                // Load cert from NV storage in 64-byte chunks
                int certSize = BitConverter.ToInt32(certSizeBlob, 0);
                byte[] rawData = new byte[certSize];
                ushort index = 0;
                ushort sizeToRead = 0;
                while (index < certSize)
                {
                    if ((certSize - index ) < 64)
                    {
                        sizeToRead = (ushort) (certSize - index);
                    }
                    else
                    {
                        sizeToRead = 64;
                    }

                    byte[] dataToRead = m_tpm[m_ownerAuth].NvRead(nvHandle, nvHandle, sizeToRead, (ushort)(index + 4));
                    
                    for (int i = 0; i < sizeToRead; i++)
                    {
                        rawData[index + i] = dataToRead[i];
                    }

                    index += sizeToRead;
                }

                X509Certificate2 certificate = null;
                RSA rsa = null;
                try
                {
                    certificate = new X509Certificate2(
                        rawData,
                        (password == null) ? String.Empty : password,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
                    rsa = certificate.GetRSAPrivateKey();
                }
                catch (Exception)
                {
                    certificate = new X509Certificate2(
                        rawData,
                        (password == null) ? String.Empty : password,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.DefaultKeySet);
                    rsa = certificate.GetRSAPrivateKey();
                }
                if (rsa != null)
                {
                    int inputBlockSize = rsa.KeySize / 8 - 42;
                    byte[] bytes1 = rsa.Encrypt(new byte[inputBlockSize], RSAEncryptionPadding.OaepSHA1);
                    byte[] bytes2 = rsa.Decrypt(bytes1, RSAEncryptionPadding.OaepSHA1);
                    if (bytes2 != null)
                    {
                        return certificate;
                    }
                }
            }
            catch (Exception e)
            {
                Utils.Trace(e, "Could not load private key for certificate " + subjectName);
            }

            return null;
        }

        private new IDictionary<string, Entry> Load(string thumbprint)
        {
            IDictionary<string, Entry> certs = base.Load(thumbprint);

            foreach(KeyValuePair<string, Entry> pair in certs)
            {
                // Create a handle based on the hash of the cert thumbprint
                ushort slotIndex = BitConverter.ToUInt16(CryptoLib.HashData(TpmAlgId.Sha256, Encoding.UTF8.GetBytes(thumbprint)), 0);
                TpmHandle nvHandle = TpmHandle.NV(slotIndex);

                // Get byte array of hash
                byte[] original = Encoding.UTF8.GetBytes(pair.Key.ToCharArray());

                // Load hash from NV storage
                byte[] rawData = m_tpm[m_ownerAuth].NvRead(nvHandle, nvHandle, (ushort) original.Length, 0);

                if (!original.IsEqual(rawData))
                {
                    // hashes don't match, don't return it
                    certs.Remove(pair.Key);
                }
            }

            return certs;
        }

#region Private Fields

        Tpm2Device m_tpmDevice = new TbsDevice();
        Tpm2 m_tpm;

        // OwnerAuth is the owner authorization value of the TPM-under-test.  We
        // assume that it (and other) auths are set to the default (null) value.
        // If running on a real TPM, which has been provisioned by Windows, this
        // value will be different. An administrator can retrieve the owner
        // authorization value from e.g. the Registry on a Windows system.
        // It is always null on a Windows 10 system, so the default constructor
        // will do, at least for Windows 10 systems!
        AuthValue m_ownerAuth = new AuthValue();

#endregion

    }
}
