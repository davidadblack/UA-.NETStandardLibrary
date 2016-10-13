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
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Text;
using Tpm2Lib;
using Windows.UI.Xaml.Controls;

namespace ProvisionTPMUWP
{
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        private void GenerateAndStoreKeys()
        {
            try
            {
                // Keypair Generator
                RsaKeyPairGenerator kpGenerator = new RsaKeyPairGenerator();
                kpGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));

                // Create a keypair
                AsymmetricCipherKeyPair keys = kpGenerator.GenerateKeyPair();

                // Connect to the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                Tpm2 tpm = new Tpm2(tpmDevice);
                AuthValue ownerAuth = new AuthValue();

                // Create a handle based on the hash of the cert thumbprint
                ushort hashcode = (ushort) keys.GetHashCode();
                TpmHandle nvHandle = TpmHandle.NV(hashcode);

                // Clean up the slot
                tpm[ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);
                
                // Export serial number, the "valid from" date (the cert will be valid for 1 year, so no need to store that date, too!), the size of the keys blob and the keys themselves
                TextWriter textWriter = new StringWriter();
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(keys);
                pemWriter.Writer.Flush();
                byte[] rawData = Encoding.ASCII.GetBytes(textWriter.ToString().ToCharArray());

                ushort size = (ushort) (sizeof(long) + sizeof(long) + rawData.Length + sizeof(int) + 64);
                ushort offset = 0;

                // Define a slot for the keys, which is 64 bytes bigger than we need as we write in 64-byte chunks
                tpm[ownerAuth].NvDefineSpace(TpmHandle.RhOwner, ownerAuth, new NvPublic(nvHandle, TpmAlgId.Sha256, NvAttr.Authread | NvAttr.Authwrite, new byte[0], size));

                // Write the serial number
                tpm[ownerAuth].NvWrite(nvHandle, nvHandle, BitConverter.GetBytes(BigInteger.ProbablePrime(120, new Random()).LongValue), offset);
                offset += sizeof(long);

                // Write the "valid from" date (today) in FileTime format
                tpm[ownerAuth].NvWrite(nvHandle, nvHandle, BitConverter.GetBytes(DateTime.Today.ToFileTime()), offset);
                offset += sizeof(long);

                // Write the size of the keys
                tpm[ownerAuth].NvWrite(nvHandle, nvHandle, BitConverter.GetBytes(rawData.Length), offset);
                offset += sizeof(int);

                // Write the keys themselves (in 64-byte chunks)
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
                            // fill the rest of the buffer with zeros
                            dataToWrite[i] = 0;
                        }
                    }

                    tpm[ownerAuth].NvWrite(nvHandle, nvHandle, dataToWrite, offset);
                    offset += 64;
                }

                tpm.Dispose();

                this.textBlock.Text += "Keys successfully generated and copied to TPM. Hashcode=" + hashcode.ToString();
            }
            catch (Exception e)
            {
                this.textBlock.Text += "Could not generate or copy keys to TPM: " + e.Message;
            }
        }

        private void button_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            GenerateAndStoreKeys();
        }
    }
}
