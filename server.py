import asyncio
import json
import argparse
import coloredlogs, logging
from aio_tcpserver import tcp_server
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from salsa20 import XSalsa20_xor

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE= 3

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = 'serverFiles'
		self.buffer = ''
		self.peername = ''
		self.algorithms = []
		self.private_key = ''
		self.public_key = ''
		self.pem_public_key = ''
		self.encriptkey = ''
		self.key=''
		self.iv = ''
		self.file_name_decrypt = 'serverFiles/fileBonito.txt'


	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT


	def data_received(self, data: bytes) -> None:
		"""
        Called when data is received from the client.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
		logger.debug('Received: {}'.format(data))
		try:
			self.buffer += data.decode()
		except:
			logger.exception('Could not decode data from client')

		idx = self.buffer.find('\r\n')

		while idx >= 0:  # While there are separators
			frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
			self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

			self.on_frame(frame)  # Process the frame
			idx = self.buffer.find('\r\n')

		if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning('Buffer to large')
			self.buffer = ''
			self.transport.close()


	def on_frame(self, frame: str) -> None:
		"""
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
		#logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()
		if mtype == 'HELLO':
			self.algorithms = message.get('data').split('_')
			if self.algorithms:
				self.keyPair()
				logger.info("Send public Key")
				self._send({'type': 'PUBLIC_KEY', 'data': base64.b64encode(self.pem_public_key).decode()})
				ret = True
			else:
				ret = False
		elif mtype == 'SECURE':
			self.encriptkey = base64.b64decode(message.get('data'))
			if self.encriptkey != '':
				logger.info("Key")
				self.getKey()
				ret = True
			else:
				ret = False
		elif mtype == 'SECURE_IV':
			logger.info("iv")
			self.iv=base64.b64decode(message.get('data'))
			if self.iv != '':
				ret = True
			else:
				ret= False
		elif mtype == 'OPEN':
			ret = self.process_open(message)
		elif mtype == 'DATA':
			ret = self.process_data(message)
		elif mtype == 'CLOSE':
			ret = self.process_close(message)
			logger.info("Decrypt file")
			self.decryptFile()
		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()


	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		fn= message['file_name'].split("/")
		file_name = fn[1]
		#file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("serverFiles"):
			try:
				os.mkdir("serverFiles")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		#self._send({'type': 'OK'})
		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True


	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True


	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE

		return True

	def keyPair(self):
		# gera a private key
		logger.info("Private Key")
		self.private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=4096,
			backend=default_backend()
		)
		logger.info("Public Key")
		# gera a public key
		self.public_key = self.private_key.public_key()
		# guarda a public key num pem
		self.pem_public_key = self.public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.debug("Send: {}".format(message))

		message_b = (json.dumps(message) + '\r\n').encode()
		self.transport.write(message_b)

	def getKey(self):
		if 'SHA256' in self.algorithms:
			self.key = self.private_key.decrypt(
				self.encriptkey,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None
				)
			)
		elif 'SHA512' in self.algorithms:
			self.key = self.private_key.decrypt(
				self.encriptkey,
				padding.OAEP(mgf=padding.MGF1(
					algorithm=hashes.SHA512()),
					algorithm=hashes.SHA512(),
					label=None
				)
			)
		else:
			logger.warning("Invalid algorithm")

	def decryptFile(self):
		with open(self.file_path, 'rb') as file:
			cryptogram = file.read()
		if "AES" in  self.algorithms:
			algorithm_name = algorithms.AES(self.key)
			if "CBC" in self.algorithms:
				cipher = Cipher(algorithm_name, modes.CBC(self.iv), backend=default_backend())
				decryptor = cipher.decryptor()
				end = decryptor.update(cryptogram) + decryptor.finalize()
				p = end[-1]
				if len(end) < p:
					raise (Exception("Invalid padding. Larger than text"))
				if not 0 < p <= algorithm_name.block_size / 8:
					raise (Exception("Invalid padding. Larger than block size"))
				pa = -1 * p
				end = end[:pa]
			elif "GCM" in self.algorithms:
				aad = str.encode(''.join(self.algorithms))
				aesgcm = AESGCM(self.key)
				end=aesgcm.decrypt(self.iv, cryptogram, aad)
			else:
				raise (Exception("Invalid mode"))

		elif "Salsa20" in self.algorithms:
			end = XSalsa20_xor(cryptogram,self.iv,self.key)
		else:
			raise (Exception("Invalid algorithm"))
		with open(self.file_name_decrypt,'w') as file:
			file.write(end.decode())

def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./serverFiles)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()


