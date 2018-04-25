#!/usr/bin/python
#coding:utf-8
import sys
import json
import time
#import xmltodict
import tornado.web
sys.path.append("../../")
from common.logger import log
#from common.constances import *
#from common.config import manager_conf as conf
#from common.authorization import Authorization

reload(sys)
sys.setdefaultencoding( "utf-8" )

class RequestLimit():
	def __init__(self):
		self.cur_requests = 1
		self.last_time = time.time()

customer_requests = {}

class HttpServer(tornado.web.RequestHandler):
	def __init__(self, application, request, **kwargs):
		tornado.web.RequestHandler.__init__(self, application, request, **kwargs)
		'''     self.auth = Authorization(log,conf.db_ip,conf.db_user,conf.db_passwd,conf.db_port,conf.db_database)
		self.algorithm = None
		self.authentication = None
		self.accesskey = None
		self.accesskey_id = None
		self.credential = None
		self.signature = None
		'''
		return;

	def print_request(self):
		log.info('**********************request***************************\n%s', self.request)
		log.info('**********************path******************************\n%s', self.request.path)
		log.info('**********************headers***************************\n%s', self.request.headers)
		log.info('**********************query*****************************\n%s', self.request.query)
		log.info('**********************arguments*************************\n%s', self.request.arguments)
		log.info('*********************query_arguments*******************\n%s', self.request.query_arguments)
		log.info('*********************body_arguments********************\n%s', self.request.body_arguments)
		log.info('**********************files*****************************\n%s', self.request.files)
		log.info('**********************connection************************\n%s', self.request.connection)
		log.info('**********************cookies***************************\n%s', self.request.cookies)
		log.info('**********************request_body***************************\n%s', self.request.body)

	def write_response(self, status, reason, res_body='', headers={}):
		log.debug('write_response(%d,%s) enter', status, reason)

		self.set_status(status, reason)

		for i in headers:
			self.set_header(i, headers[i])

		#去掉Last-Modified
		self.set_header('Last-Modified', '')

		#Content-Type
		if '' != res_body and 'Content-Type' not in headers:
			self.set_header('Content-Type', 'text/plain')

		#body
		if '' != res_body:
			self.write(res_body)
		#else:
		#    self.write('test string')

		log.debug('write_response(%d,%s) out', status, reason)

	def write_error_response(self,status, reason, message, headers={}):
		log.info('write_error_response(%d,%s,%s) enter', status, reason, message)

		#返回码和reason
		self.set_status(status, reason)

		#设置头
		for i in headers:
			self.set_header(i, headers[i])
		log.debug('error body:%s', message)

		self.write(message)
		self.finish()
		log.info('write_error_response(%d,%s,%s) out', status, reason, message)

	def handle_request(self):
		self.write_error_response(404,'Not Found','Not Found, long live')
		log.debug('handle_request() out')

	def check_requests_times(self):
		log.debug('HttpServer.check_requests_times enter TODO');
		#TODO
		return True;

	def init_request(self):
		#初始化请求，连接数据库，解析参数，判断是否完整
		return True,200,'OK','';

	def handle(self,method):
		log.debug('HttpServer.handle enter')
		self.print_request()
		ret, status, reason, body = True, 200, 'OK', ''
		if self.check_requests_times() == False:
			self.write_error_response(403, 'request so fast', 'request so fast')
			return
		ret, status, reason, body = self.init_request();
		if ret == False:
			self.write_error_response(status, reason, body);
			return
		ret, status, reason, body = self.handle_request();
		if ret == False:
			self.write_error_response(status, reason, body);
			return
		self.write_response(status, reason, body);
		log.debug('HttpServer.handle normal out. err cannot come here')

	def get(self):
		log.debug('HttpServer.get enter')
		self.handle('GET')
		log.debug('HttpServer.get out')

	def post(self):
		log.debug('HttpServer.post enter')
		self.handle('POST')
		log.debug('HttpServer.post out')


if __name__ == '__main__':
	pass
