using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace N_m3u8DL_CLI
{
	//thanks https://github.com/xhlove
	class DecrypterYK
	{
		private static byte SYNC_BYTE = 0x47;
		private static int TS_PACKET_LENGTH = 188;

		//合并byte[]
		private static byte[] Combine(params byte[][] arrays)
		{
			byte[] rv = new byte[arrays.Sum(a => a.Length)];
			int offset = 0;
			foreach (byte[] array in arrays)
			{
				//Buffer.BlockCopy(array, 0, rv, offset, array.Length);
				Array.Copy(array, 0, rv, offset, array.Length);
				offset += array.Length;
			}
			return rv;
		}

		//按照指定大小分割byte[]
		public static List<byte[]> SplitByteArray(byte[] bytes, int BlockLength)
		{
			List<byte[]> _byteArrayList = new List<byte[]>();
			byte[] buffer;
			for (int i = 0; i < bytes.Length; i += BlockLength)
			{
				if ((i + BlockLength) > bytes.Length)
				{
					buffer = new byte[bytes.Length - i];
					Buffer.BlockCopy(bytes, i, buffer, 0, bytes.Length - i);
				}
				else
				{
					buffer = new byte[BlockLength];
					Buffer.BlockCopy(bytes, i, buffer, 0, BlockLength);
				}

				_byteArrayList.Add(buffer);
			}
			return _byteArrayList;
		}

		private static byte[] DecryptAES(ICryptoTransform cryptoTransform, byte[] encryptData)
		{
			//16取余结果后面的部分视为不需要解密的部分
			int inputCount = encryptData.Length - encryptData.Length % 16;
			byte[] array = cryptoTransform.TransformFinalBlock(encryptData, 0, inputCount);
			//将解密好的部分覆盖掉原数组
			Array.Copy(array, encryptData, array.Length);
			return encryptData;
		}

		//找TS流起始帧位置 0x47
		private static int GetPacketStartOffset(byte[] raw)
		{
			if (raw.Length == TS_PACKET_LENGTH)
				return 0;
			for (int i = 0; i < raw.Length; i++)
			{
				if (raw[i] == SYNC_BYTE && raw[i + TS_PACKET_LENGTH] == SYNC_BYTE)
					return i;
			}
			return -1;
		}

		public static byte[] Decrypt(byte[] encrtpyData, byte[] keybuffer, byte[] ivByte)
		{
			//流操作指针
			var pointer = 0;
			MemoryStream bStream = new MemoryStream();

			Aes aes = Aes.Create("AES");
			aes.BlockSize = 128;
			aes.KeySize = 128;
			aes.Key = keybuffer;
			aes.IV = ivByte;
			aes.Mode = CipherMode.ECB;
			aes.Padding = PaddingMode.None;
			ICryptoTransform cryptoTransform = aes.CreateDecryptor();

			MemoryStream decryptStream = new MemoryStream();
			var offset = GetPacketStartOffset(encrtpyData);
			MemoryStream inputStream = new MemoryStream(encrtpyData.Skip(offset - 1).ToArray());
			var inputStreamLength = inputStream.Length;
			//按照188字节分组
			//var packets = SplitByteArray(encrtpyData, TS_PACKET_LENGTH);
			//var packetsNum = packets.Count;
			var nowPidHeaders = new List<byte[]>();
			var first = true;
			var pmtPID = -1;
			//开始处理
			while (pointer < inputStreamLength) 
			{
				var nowPacket = new byte[188];
				var readLen = inputStream.Read(nowPacket, 0, TS_PACKET_LENGTH);
				pointer += readLen;

				//syncword不为47就不处理
				if (nowPacket[0] != 0x47)
					continue;


				var payloadUnitStartIndicator = Convert.ToBoolean(64 & nowPacket[1]);
				//第二三字节的二进制字符串，可以取出pid
				int pid = (31 & nowPacket[1]) << 8 | nowPacket[2];

				//前4个字节会决定这个packet是音频、视频还是meta(以及其他)，不处理
				var preOffset = 4;
				if (1 < (48 & nowPacket[3]) >> 4)
				{
					preOffset += nowPacket[preOffset] + 1;
				}

				//通过PAT包寻找PMT包的pid
				if (pid == 0)
				{
					pmtPID = GetPMTPid(nowPacket.Skip(preOffset + 1).ToArray());
				}
				
				//跳过空包
				if (pid == 8191)
					continue;

				//需要保留的pat、pmt、sdt等包，不处理
				//https://en.wikipedia.org/wiki/MPEG_transport_stream
				if ((pid >= 0 && pid <= 31) || pid == pmtPID) 
				{
					decryptStream.Write(nowPacket, 0, nowPacket.Length);
					continue;
				}


				var _a = nowPacket.Take(preOffset).ToArray();
				var _b = nowPacket.Skip(preOffset).ToArray();

				//第一次
				if (first) { payloadUnitStartIndicator = false; first = false; }
				//直接将前部分加入header
				nowPidHeaders.Add(_a);
				//Console.WriteLine($"{pid} {payloadUnitStartIndicator}");Console.ReadKey();
				if (!payloadUnitStartIndicator) 
				{
					bStream.Write(_b, 0, _b.Length);
					continue;
				}
				else
				{
					//所有后半部分的byte[]
					var _bData = bStream.ToArray();
					//真正需要解密的开始位置是第8位的值+9
					var skipCount = _bData[8] + 9;
					//真正需要解密的数据
					var toDecryptData = _bData.Skip(skipCount).ToArray();
					//解密
					var preDecryptData = DecryptAES(cryptoTransform, toDecryptData);
					//要分配的数据
					var nData = new MemoryStream(Combine(_bData.Take(skipCount).ToArray(), preDecryptData));

					for (int j = 0; j < nowPidHeaders.Count - 1; j++)
					{
						decryptStream.Write(nowPidHeaders[j], 0, nowPidHeaders[j].Length);
						var len = TS_PACKET_LENGTH - nowPidHeaders[j].Length;
						var btmp = new byte[len];
						nData.Read(btmp, 0, len);
						decryptStream.Write(btmp, 0, btmp.Length);
					}

					//整理解密数据
					nowPidHeaders.RemoveRange(0, nowPidHeaders.Count - 1);
					bStream = new MemoryStream();
					bStream.Write(_b, 0, _b.Length);
				}
			}

			if (bStream.ToArray().Length > 0)
			{
				//所有后半部分的byte[]
				var _bData = bStream.ToArray();
				//firstPacket时，真正需要解密的开始位置是第8位的值+9
				var skipCount = _bData[8] + 9;
				//真正需要解密的数据
				var toDecryptData = _bData.Skip(skipCount).ToArray();
				//解密
				var preDecryptData = DecryptAES(cryptoTransform, toDecryptData);
				//要分配的数据
				var nData = new MemoryStream(Combine(_bData.Take(skipCount).ToArray(), preDecryptData));

				for (int j = 0; j < nowPidHeaders.Count; j++)
				{
					decryptStream.Write(nowPidHeaders[j], 0, nowPidHeaders[j].Length);
					var len = TS_PACKET_LENGTH - nowPidHeaders[j].Length;
					var btmp = new byte[len];
					nData.Read(btmp, 0, len);
					decryptStream.Write(btmp, 0, btmp.Length);
				}
				//整理解密数据
				var tmp = Combine(nowPidHeaders.Take(nowPidHeaders.Count).ToArray());
				decryptStream.Write(tmp, 0, tmp.Length);
			}
			decryptStream.Close();
			return decryptStream.ToArray();
		}

		private static int GetPMTPid(byte[] nowPacket)
		{
			return (31 & nowPacket[10]) << 8 | nowPacket[11];
		}
	}
}
