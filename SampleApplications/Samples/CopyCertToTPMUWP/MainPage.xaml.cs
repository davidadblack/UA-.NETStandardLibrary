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
using Tpm2Lib;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI.Xaml.Controls;

namespace CopyCertToTPMUWP
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        private void CopyCert(string[] args)
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
                TpmHandle nvHandle = TpmHandle.NV(3001/*certificate.Thumbprint.GetHashCode()*/);

                // Clean up the slot
                tpm[ownerAuth]._AllowErrors().NvUndefineSpace(TpmHandle.RhOwner, nvHandle);

                // Define a slot for the thumbprint, which is 64 bytes bigger than we need as we write in 64-byte chunks
                AuthValue nvAuth = AuthValue.FromRandom(8);
                ushort size = (ushort)(certificate.RawData.Length + 4 + 64);
                
                tpm[ownerAuth].NvDefineSpace(TpmHandle.RhOwner, nvAuth, new NvPublic(nvHandle, TpmAlgId.Sha1, NvAttr.Authread | NvAttr.Authwrite, new byte[0], size));

                // Write the size of the cert (4 bytes)
                ushort offset = 0;
                tpm[nvAuth].NvWrite(nvHandle, nvHandle, BitConverter.GetBytes(certificate.RawData.Length), offset);
                offset += 4;

                // Write the cert itself (in 64-byte chunks)
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
                            // fill the rest of the buffer with zeros
                            dataToWrite[i] = 0;
                        }
                    }
                    
                    tpm[nvAuth].NvWrite(nvHandle, nvHandle, dataToWrite, offset);
                    offset += 64;
                }

                tpm.Dispose();

                this.textBlock.Text += "Certificate successfully copied to TPM!";
            }
            catch (Exception e)
            {
                this.textBlock.Text += "Could not copy certificate to TPM: " + e.Message;
            }
        }

        private async void button_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            FileOpenPicker openPicker = new FileOpenPicker();
            openPicker.ViewMode = PickerViewMode.List;
            openPicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            openPicker.FileTypeFilter.Add(".pfx");
            StorageFile file = await openPicker.PickSingleFileAsync();

            string[] args = new string[1];
            if (file != null)
            {
                args[0] = file.Path;
            }
            else
            {
                // if file pickers are not supported (like in Windows 10 IoT Core), try the application data directory with a known file name like "cert.pfx"
                args[0] = ApplicationData.Current.LocalFolder.Path + "\\cert.pfx";
            }

            CopyCert(args);
        }
    }
}
