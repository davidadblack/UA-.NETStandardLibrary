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
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace Opc.Ua
{
    /// <summary>
    /// Provides access to a simple file based certificate store.
    /// </summary>
    public class TPMCertificateStore : DirectoryCertificateStore
    {
        private static TPMCertificateStore m_instance = null;

        public new static ICertificateStore Instance
        {
            get
            {
                if (m_instance == null)
                {
                    lock (m_lock)
                    {
                        if (m_instance == null)
                        {
                            m_instance = new TPMCertificateStore();
                            Utils.CurrentCertificateStore = m_instance;
                        }
                    }
                }

                return m_instance;
            }
        }

        private TPMCertificateStore() { }

        public override void Open(string location)
        {
            lock (m_lock)
            {
                base.Open(location);
                m_tpmDevice.Connect();
                m_tpm = new Tpm2(m_tpmDevice);
            }
        }

        public override void Close()
        {
            lock (m_lock)
            {
                m_tpm.Dispose();
                base.Close();
            }
        }

        public override Task Add(X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException("certificate");
         
            lock (m_lock)
            {
                try
                {
                    // Create a handle based on the hash of the cert thumbprint
                    ushort slotIndex = BitConverter.ToUInt16(CryptoLib.HashData(TpmAlgId.Sha256, Encoding.UTF8.GetBytes(certificate.Thumbprint)), 0);
                    TpmHandle nvHandle = TpmHandle.NV(slotIndex);

                    // Clean up the slot
                    m_tpm[m_ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);

                    // Define a slot for the thumbprint
                    m_tpm[m_ownerAuth].NvDefineSpace(TpmHandle.RhOwner, m_ownerAuth, new NvPublic(nvHandle, TpmAlgId.Sha256, NvAttr.Authread | NvAttr.Authwrite, new byte[0], (ushort)certificate.Thumbprint.ToCharArray().Length));

                    // Write the thumbprint
                    m_tpm[m_ownerAuth].NvWrite(nvHandle, nvHandle, Encoding.UTF8.GetBytes(certificate.Thumbprint.ToCharArray()), 0);
                }
                catch (Exception e)
                {
                    Utils.Trace(e, "Could not add application certificate thumprint to TPM NV storage!");
                }
            }

            return base.Add(certificate);
        }

        public override Task<bool> Delete(string thumbprint)
        {
            lock (m_lock)
            {
                try
                {
                    // Create a handle based on the hash of the cert thumbprint
                    ushort slotIndex = BitConverter.ToUInt16(CryptoLib.HashData(TpmAlgId.Sha256, Encoding.UTF8.GetBytes(thumbprint)), 0);
                    TpmHandle nvHandle = TpmHandle.NV(slotIndex);

                    // Delete hash of thumbprint from NV storage
                    m_tpm[m_ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);
                }
                catch (Exception e)
                {
                    Utils.Trace(e, "Could not delete application certificate thumprint from TPM NV storage!");
                }
            }

            return base.Delete(thumbprint);
        }
   
        public override X509Certificate2 LoadApplicationCertificate(string thumbprint, string subjectName, string applicationURI, string password)
        {
            try
            {
                // Create a handle based on the hash of the keys
                ushort slotIndex = ushort.Parse(thumbprint);
                TpmHandle nvHandle = TpmHandle.NV(slotIndex);
                ushort offset = 0;

                // Read the serial number
                byte[] serialNumber = m_tpm[m_ownerAuth].NvRead(nvHandle, nvHandle, sizeof(long), offset);
                offset += sizeof(long);

                // Read the "valid from" date (today) in FileTime format
                byte[] validFrom = m_tpm[m_ownerAuth].NvRead(nvHandle, nvHandle, sizeof(long), offset);
                offset += sizeof(long);

                // Read size of keys from NV storage (located in the first 4 bytes)
                byte[] certSizeBlob = m_tpm[m_ownerAuth].NvRead(nvHandle, nvHandle, sizeof(int), offset);
                offset += sizeof(int);

                // Read keys from NV storage in 64-byte chunks
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

                    byte[] dataToRead = m_tpm[m_ownerAuth].NvRead(nvHandle, nvHandle, sizeToRead, offset);
                    offset += sizeToRead;

                    for (int i = 0; i < sizeToRead; i++)
                    {
                        rawData[index + i] = dataToRead[i];
                    }

                    index += sizeToRead;
                }

                // Import
                TextReader textReader = new StringReader(new string(Encoding.ASCII.GetChars(rawData)));
                PemReader pemReader = new PemReader(textReader);
                AsymmetricCipherKeyPair keys = (AsymmetricCipherKeyPair) pemReader.ReadObject();

                X509Name CN = new X509Name("CN="+ subjectName + ",DC=" + Utils.GetHostName());
                BigInteger SN = new BigInteger(serialNumber).Abs();
                DateTime validFromDate = DateTime.FromFileTime(BitConverter.ToInt64(validFrom, 0));

                // Certificate Generator
                X509V3CertificateGenerator cGenerator = new X509V3CertificateGenerator();
                cGenerator.SetSerialNumber(SN);
                cGenerator.SetSubjectDN(CN);
                cGenerator.SetIssuerDN(CN);
                cGenerator.SetNotBefore(validFromDate);
                cGenerator.SetNotAfter(validFromDate.AddYears(1));
                cGenerator.SetPublicKey(keys.Public);
                cGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(new List<DerObjectIdentifier>() { new DerObjectIdentifier("1.3.6.1.5.5.7.3.1") }));
                cGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keys.Public), new GeneralNames(new GeneralName(CN)), SN));
                cGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, applicationURI)));

                ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA1withRSA", keys.Private, new SecureRandom());
                Org.BouncyCastle.X509.X509Certificate cert = cGenerator.Generate(signatureFactory);
                X509Certificate2 certificate = new X509Certificate2(cert.GetEncoded());
                
                RSACng rsa = new RSACng();
                RsaPrivateCrtKeyParameters keyParams = (RsaPrivateCrtKeyParameters) keys.Private;

                m_RSAParams = new RSAParameters();

                m_RSAParams.Modulus = new byte[keyParams.Modulus.ToByteArrayUnsigned().Length];
                keyParams.Modulus.ToByteArrayUnsigned().CopyTo(m_RSAParams.Modulus, 0);

                m_RSAParams.P = new byte[keyParams.P.ToByteArrayUnsigned().Length];
                keyParams.P.ToByteArrayUnsigned().CopyTo(m_RSAParams.P, 0);

                m_RSAParams.Q = new byte[keyParams.Q.ToByteArrayUnsigned().Length];
                keyParams.Q.ToByteArrayUnsigned().CopyTo(m_RSAParams.Q, 0);

                m_RSAParams.DP = new byte[keyParams.DP.ToByteArrayUnsigned().Length];
                keyParams.DP.ToByteArrayUnsigned().CopyTo(m_RSAParams.DP, 0);

                m_RSAParams.DQ = new byte[keyParams.DQ.ToByteArrayUnsigned().Length];
                keyParams.DQ.ToByteArrayUnsigned().CopyTo(m_RSAParams.DQ, 0);

                m_RSAParams.InverseQ = new byte[keyParams.QInv.ToByteArrayUnsigned().Length];
                keyParams.QInv.ToByteArrayUnsigned().CopyTo(m_RSAParams.InverseQ, 0);

                m_RSAParams.D = new byte[keyParams.Exponent.ToByteArrayUnsigned().Length];
                keyParams.Exponent.ToByteArrayUnsigned().CopyTo(m_RSAParams.D, 0);

                m_RSAParams.Exponent = new byte[keyParams.PublicExponent.ToByteArrayUnsigned().Length];
                keyParams.PublicExponent.ToByteArrayUnsigned().CopyTo(m_RSAParams.Exponent, 0);

                rsa.ImportParameters(m_RSAParams);
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
                Utils.Trace(e, "Could not load application certificate " + subjectName);
            }

            return null;
        }

        protected override IDictionary<string, Entry> Load(string thumbprint)
        {
            IDictionary<string, Entry> certs = base.Load(thumbprint);

            foreach(KeyValuePair<string, Entry> pair in certs)
            {
                try
                {
                    // Create a handle based on the hash of the cert thumbprint
                    ushort slotIndex = BitConverter.ToUInt16(CryptoLib.HashData(TpmAlgId.Sha256, Encoding.UTF8.GetBytes(thumbprint)), 0);
                    TpmHandle nvHandle = TpmHandle.NV(slotIndex);

                    // Get byte array of hash
                    byte[] original = Encoding.UTF8.GetBytes(pair.Key.ToCharArray());

                    // Load hash from NV storage
                    byte[] rawData = m_tpm[m_ownerAuth].NvRead(nvHandle, nvHandle, (ushort)original.Length, 0);

                    if (!original.IsEqual(rawData))
                    {
                        // hashes don't match, don't return it
                        certs.Remove(pair.Key);
                    }
                }
                catch (Exception e)
                {
                    Utils.Trace(e, "Could not check application certificate thumprint in TPM NV storage!");
                }
            }

            return certs;
        }

        public override RSA GetRSACSP(X509Certificate2 encryptingCertificate)
        {
            RSA rsa = null;
            if (encryptingCertificate.HasPrivateKey)
            {
                rsa = encryptingCertificate.GetRSAPrivateKey();
            }
            else
            {
                rsa = new RSACng();
                rsa.ImportParameters(m_RSAParams);
            }

            return rsa;
        }

#region Private Fields

        private RSAParameters m_RSAParams;
        private Tpm2Device m_tpmDevice = new TbsDevice();
        private Tpm2 m_tpm;

        // OwnerAuth is the owner authorization value of the TPM-under-test.  We
        // assume that it (and other) auths are set to the default (null) value.
        // If running on a real TPM, which has been provisioned by Windows, this
        // value will be different. An administrator can retrieve the owner
        // authorization value from e.g. the Registry on a Windows system.
        // It is always null on a Windows 10 system, so the default constructor
        // will do, at least for Windows 10 systems!
        private AuthValue m_ownerAuth = new AuthValue();

#endregion

    }
}
