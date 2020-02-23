﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace N_m3u8DL_CLI
{
    class Downloader
    {
        public static bool YouKuAES = false;

        private int timeOut = 0;
        private int retry = 5;
        private int count = 0;
        private int segIndex = 0;
        private double segDur = 0;
        private string fileUrl = string.Empty;
        private string savePath = string.Empty;
        private string headers = string.Empty;
        private string method = string.Empty;
        private string key = string.Empty;
        private string iv = string.Empty;
        private string liveFile = string.Empty;
        private long expectByte = -1;
        private long startByte = 0;
        private bool isLive = false;
        private bool isDone = false;
        private bool firstSeg = true;
        private FileStream liveStream = null;

        public string FileUrl { get => fileUrl; set => fileUrl = value; }
        public string SavePath { get => savePath; set => savePath = value; }
        public string Headers { get => headers; set => headers = value; }
        public string Method { get => method; set => method = value; }
        public string Key { get => key; set => key = value; }
        public string Iv { get => iv; set => iv = value; }
        public bool IsLive { get => isLive; set => isLive = value; }
        public int Retry { get => retry; set => retry = value; }
        public bool IsDone { get => isDone; set => isDone = value; }
        public int SegIndex { get => segIndex; set => segIndex = value; }
        public int TimeOut { get => timeOut; set => timeOut = value; }
        public FileStream LiveStream { get => liveStream; set => liveStream = value; }
        public string LiveFile { get => liveFile; set => liveFile = value; }
        public long ExpectByte { get => expectByte; set => expectByte = value; }
        public long StartByte { get => startByte; set => startByte = value; }
        public double SegDur { get => segDur; set => segDur = value; }

        //重写WebClinet
        //private class WebClient : System.Net.WebClient
        //{
        //    protected override WebRequest GetWebRequest(Uri uri)
        //    {
        //        WebRequest lWebRequest = base.GetWebRequest(uri);
        //        lWebRequest.Timeout = TimeOut;
        //        ((HttpWebRequest)lWebRequest).ReadWriteTimeout = TimeOut;
        //        return lWebRequest;
        //    }
        //}

        //WebClient client = new WebClient();


        public void Down()
        {
            try
            {
                //直播下载
                if (IsLive)
                {
                    IsDone = false;  //设置为未完成下载

                    if (Method == "NONE" || method.Contains("NOTSUPPORTED")) 
                    {
                        LOGGER.PrintLine("<" + SegIndex + " Downloading>");
                        byte[] segBuff = Global.HttpDownloadFileToBytes(fileUrl, Headers, TimeOut);
                        //byte[] segBuff = Global.WebClientDownloadToBytes(fileUrl, Headers);
                        Global.AppendBytesToFileStreamAndDoNotClose(LiveStream, segBuff);
                        LOGGER.PrintLine("<" + SegIndex + " Complete>\r\n");
                        IsDone = true;
                    }
                    else if (Method == "AES-128")
                    {
                        LOGGER.PrintLine("<" + SegIndex + " Downloading>");
                        byte[] encryptedBuff = Global.HttpDownloadFileToBytes(fileUrl, Headers, TimeOut);
                        //byte[] encryptedBuff = Global.WebClientDownloadToBytes(fileUrl, Headers);
                        byte[] decryptBuff = null;
                        if (YouKuAES)
                        {
                            decryptBuff = DecrypterYK.Decrypt(
                                encryptedBuff,
                                Convert.FromBase64String(Key),
                                Decrypter.HexStringToBytes(Iv)
                                );
                        }
                        else
                        {
                            decryptBuff = Decrypter.AES128Decrypt(
                                encryptedBuff,
                                Convert.FromBase64String(Key),
                                Decrypter.HexStringToBytes(Iv)
                                );
                        }
                        Global.AppendBytesToFileStreamAndDoNotClose(LiveStream, decryptBuff);
                        LOGGER.PrintLine("<" + SegIndex + " Complete>\r\n");
                        IsDone = true;
                    }
                    else
                    {
                        //LOGGER.PrintLine("不支持这种加密方式!", LOGGER.Error);
                        IsDone = true;
                    }
                    if (firstSeg && Global.FileSize(LiveFile) != 0)
                    {
                        LOGGER.STOPLOG = false;  //记录日志
                        foreach (string ss in (string[])Global.GetVideoInfo(LiveFile).ToArray(typeof(string)))
                        {
                            LOGGER.WriteLine(ss.Trim());
                        }
                        firstSeg = false;
                        LOGGER.STOPLOG = true;  //停止记录日志
                    }
                    return;
                }
                //点播下载
                else
                {
                    if (!Directory.Exists(Path.GetDirectoryName(SavePath)))
                        Directory.CreateDirectory(Path.GetDirectoryName(SavePath)); //新建文件夹  
                    //是否存在文件，存在则不下载
                    if (File.Exists(Path.GetDirectoryName(savePath) + "\\" + Path.GetFileNameWithoutExtension(savePath) + ".ts"))
                    {
                        Global.BYTEDOWN++; //防止被速度监控程序杀死
                        //Console.WriteLine("Exists " + Path.GetFileNameWithoutExtension(savePath) + ".ts");
                        return;
                    }
                    //Console.WriteLine("开始下载 " + fileUrl);
                    //本地文件
                    if (fileUrl.StartsWith("file:"))
                    {
                        Uri t = new Uri(fileUrl);
                        fileUrl = t.LocalPath;
                        if (File.Exists(fileUrl))
                        {
                            if (ExpectByte == -1)  //没有RANGE
                            {
                                FileInfo fi = new FileInfo(fileUrl);
                                fi.CopyTo(savePath);
                                Global.BYTEDOWN += fi.Length;
                            }
                            else
                            {
                                FileStream stream = new FileInfo(fileUrl).OpenRead();
                                //seek文件
                                stream.Seek(StartByte, SeekOrigin.Begin);
                                Byte[] buffer = new Byte[ExpectByte];
                                //从流中读取字节块并将该数据写入给定缓冲区buffer中
                                stream.Read(buffer, 0, Convert.ToInt32(buffer.Length));
                                stream.Close();
                                //写出文件
                                MemoryStream m = new MemoryStream(buffer);
                                FileStream fs = new FileStream(savePath, FileMode.OpenOrCreate);
                                m.WriteTo(fs);
                                m.Close();
                                fs.Close();
                                m = null;
                                fs = null;
                            }
                        }
                    }
                    else
                    {
                        //下载
                        Global.HttpDownloadFile(fileUrl, savePath, TimeOut, Headers, StartByte, ExpectByte);
                    }
                }
                if (File.Exists(savePath) && Global.ShouldStop == false) 
                {
                    FileInfo fi = new FileInfo(savePath);
                    if (Method == "NONE" || method.Contains("NOTSUPPORTED"))
                    {
                        fi.MoveTo(Path.GetDirectoryName(savePath) + "\\" + Path.GetFileNameWithoutExtension(savePath) + ".ts");
                        DownloadManager.DownloadedSize += fi.Length;
                        //Console.WriteLine(Path.GetFileNameWithoutExtension(savePath) + " Completed.");
                    }
                    else if (File.Exists(fi.FullName)
                        && Method == "AES-128") 
                    {
                        //解密
                        try
                        {
                            byte[] decryptBuff = null;
                            if (YouKuAES)
                            {
                                decryptBuff = DecrypterYK.Decrypt(
                                    File.ReadAllBytes(fi.FullName),
                                    Convert.FromBase64String(Key),
                                    Decrypter.HexStringToBytes(Iv)
                                    );
                            }
                            else
                            {
                                decryptBuff = Decrypter.AES128Decrypt(
                                    fi.FullName,
                                    Convert.FromBase64String(Key),
                                    Decrypter.HexStringToBytes(Iv)
                                    );
                            }
                            FileStream fs = new FileStream(Path.GetDirectoryName(savePath) + "\\" + Path.GetFileNameWithoutExtension(savePath) + ".ts", FileMode.Create);
                            fs.Write(decryptBuff, 0, decryptBuff.Length);
                            fs.Close();
                            DownloadManager.DownloadedSize += fi.Length;
                            fi.Delete();
                            //Console.WriteLine(Path.GetFileNameWithoutExtension(savePath) + " Completed & Decrypted.");
                        }
                        catch (Exception ex)
                        {
                            LOGGER.PrintLine(ex.Message, LOGGER.Error);
                            LOGGER.WriteLineError(ex.Message);
                            Environment.Exit(-1);
                        }
                    }
                    else
                    {
                        LOGGER.WriteLineError("Something was wrong!");
                        LOGGER.PrintLine("遇到了某些错误!", LOGGER.Error);
                        return;
                    }
                    return;
                }
            }
            catch (Exception ex)
            {
                LOGGER.WriteLineError(ex.Message);
                if (ex.Message.Contains("404"))
                {
                    IsDone = true;
                    return;
                }
                else if (IsLive && count++ < Retry) 
                {
                    Thread.Sleep(5000);
                    Down();
                }
            }
        }
    }
}
