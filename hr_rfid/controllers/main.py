# -*- coding: utf-8 -*-

from odoo import http, fields, exceptions, _
from odoo.http import request
import datetime
import json
import traceback


class WebRfidController(http.Controller):
    @http.route(['/hr/rfid/event'], type='json', auth='none', method=['POST'], csrf=False)
    def post_event(self, **post):
        if 'convertor' not in post or 'key' not in post:
            raise exceptions.ValidationError(_('Received a json request without the required fields:\n%s')
                                             % json.dumps(post))

        sys_ev_env = request.env['hr.rfid.event.system'].sudo()
        ws_env = request.env['hr.rfid.webstack'].sudo()
        ws = ws_env.search([ ('serial', '=', str(post['convertor'])) ])

        if not ws:
            ws_env.create({
                'name': 'Module ' + str(post['convertor']),
                'serial': str(post['convertor']),
                'key': post['key'],
                'last_ip': request.httprequest.environ['REMOTE_ADDR'],
                'updated_at': fields.Datetime.now(),
            })
            return { 'status': 400 }

        if ws.key != post['key']:
            sys_ev_env.report(ws, post, 'Webstack key and key in json did not match')
            return { 'status': 400 }

        last_ip = request.httprequest.environ['REMOTE_ADDR']

        try:
            return ws.deal_with_event(post, last_ip)
        except (KeyError, exceptions.UserError, exceptions.AccessError, exceptions.AccessDenied,
                exceptions.MissingError, exceptions.ValidationError, exceptions.DeferredException) as __:
            request.env['hr.rfid.event.system'].sudo().create({
                'webstack_id': ws.id,
                'timestamp': fields.Datetime.now(),
                'error_description': traceback.format_exc(),
                'input_js': json.dumps(post),
            })
            return { 'status': 500 }
