# -*- coding: utf-8 -*-
from odoo import api, fields, models, exceptions, _
from datetime import datetime, timedelta
from ..wizards.helpers import create_and_ret_d_box, return_wiz_form_view
import socket
import http.client
import json
import base64
import pytz

# put POSIX 'Etc/*' entries at the end to avoid confusing users - see bug 1086728
_tzs = [(tz, tz) for tz in sorted(pytz.all_timezones, key=lambda tz: tz if not tz.startswith('Etc/') else '_')]
def _tz_get(self):
    return _tzs


class HrRfidWebstackDiscovery(models.TransientModel):
    _name = 'hr.rfid.webstack.discovery'
    _description = 'Webstack discovery'

    found_webstacks = fields.Many2many(
        comodel_name='hr.rfid.webstack',
        relation='hr_rfid_webstack_discovery_all',
        column1='wiz',
        column2='ws',
        string='Found modules',
        readonly=True,
        help='Modules that were just found during the discovery process',
    )

    setup_and_set_to_active = fields.Many2many(
        comodel_name='hr.rfid.webstack',
        relation='hr_rfid_webstack_discovery_set',
        column1='wiz',
        column2='ws',
        string='Setup and activate',
        help='Modules to automatically setup for the odoo and activate',
    )

    state = fields.Selection(
        [ ('pre_discovery', 'pre_discovery'), ('post_discovery', 'post_discovery') ],
        default='pre_discovery'
    )

    @api.multi
    def discover(self):
        self.ensure_one()
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_sock.bind(("", 30303))

        send_msg = b'Discovery:'
        res = udp_sock.sendto(send_msg, ('<broadcast>', 30303))
        if res is False:
            udp_sock.close()
            return

        ws_env = self.env['hr.rfid.webstack']

        while True:
            udp_sock.settimeout(0.5)
            try:
                data, addr = udp_sock.recvfrom(1024)
                data = data.decode().split('\n')[:-1]
                data = list(map(str.strip, data))
                if len(data) == 0 or len(data) > 100:
                    continue
                if len(ws_env.search([('serial', '=', data[4])])) > 0:
                    continue
                module = {
                    'last_ip':    addr[0],
                    'name':       data[0],
                    'version':    data[3],
                    'hw_version': data[2],
                    'serial':     data[4],
                    'available': 'u',
                }
                env = ws_env.sudo()
                module = env.create(module)
                self.found_webstacks += module
                try:
                    module.action_check_if_ws_available()
                except exceptions.ValidationError as __:
                    pass
            except socket.timeout:
                break

        udp_sock.close()
        self.write({ 'state': 'post_discovery' })
        return return_wiz_form_view(self._name, self.id)

    @api.multi
    def setup_modules(self):
        self.ensure_one()
        for ws in self.setup_and_set_to_active:
            ws.action_set_webstack_settings()
            ws.action_set_active()

        return {
            'type': 'ir.actions.client',
            'tag': 'reload',
        }


class HrRfidWebstack(models.Model):
    _name = 'hr.rfid.webstack'
    _inherit = ['mail.thread']
    _description = 'Module'

    name = fields.Char(
        string='Name',
        help='A label to easily differentiate modules',
        required=True,
        index=True,
        track_visibility='onchange',
    )

    tz = fields.Selection(
        _tz_get,
        string='Timezone',
        default=lambda self: self._context.get('tz'),
        help='If not set, will assume GMT',
    )

    tz_offset = fields.Char(
        string='Timezone offset',
        compute='_compute_tz_offset',
    )

    serial = fields.Char(
        string='Serial number',
        help='Unique number to differentiate all modules',
        limit=6,
        index=True,
        readonly=True,
    )

    key = fields.Char(
        string='Key',
        limit=4,
        index=True,
        default='0000',
        track_visibility='onchange',
    )

    ws_active = fields.Boolean(
        string='Active',
        help='Will accept events from module if true',
        default=False,
        track_visibility='onchange',
    )

    version = fields.Char(
        string='Version',
        help='Software version of the module',
        limit=6,
    )

    hw_version = fields.Char(
        string='Hardware Version',
        help='Hardware version of the module',
        limit=6,
    )

    behind_nat = fields.Boolean(
        string='Behind NAT',
        help='Whether we can create a direct connection to the module or not',
        required=True,
        default=True,
    )

    last_ip = fields.Char(
        string='Last IP',
        help='Last IP the module connected from',
        limit=26,
    )

    updated_at = fields.Datetime(
        string='Last Update',
        help='The last date we received an event from the module',
    )

    controllers = fields.One2many(
        'hr.rfid.ctrl',
        'webstack_id',
        string='Controllers',
        help='Controllers that this WebStack manages'
    )

    system_event_ids = fields.One2many(
        'hr.rfid.event.system',
        'webstack_id',
        string='Errors',
        help='Errors that we have received from the module'
    )

    command_ids = fields.One2many(
        'hr.rfid.command',
        'webstack_id',
        string='Commands',
        help='Commands that have been or are in queue to send to this module.',
    )

    http_link = fields.Char(
        compute='_compute_http_link'
    )

    module_username = fields.Selection(
        selection=[ ('admin', 'Admin'), ('sdk', 'SDK') ],
        string='Module Username',
        help='Username for the admin account for the module',
        default='admin',
    )

    module_password = fields.Char(
        string='Module Password',
        help='Password for the admin account for the module',
        default='',
    )

    available = fields.Selection(
        selection=[ ('u', 'Unavailable'), ('a', 'Available') ],
        string='Available?',
        help='Whether the module was available the last time Odoo tried to connect to it.',
        default='u',
    )

    _sql_constraints = [ ('rfid_webstack_serial_unique', 'unique(serial)',
                          'Serial number for webstacks must be unique!') ]

    @api.one
    def action_set_webstack_settings(self):
        odoo_url = str(self.env['ir.config_parameter'].get_param('web.base.url'))
        splits = odoo_url.split(':')
        odoo_url = splits[1][2:]
        if len(splits) == 3:
            odoo_port = int(splits[2], 10)
        else:
            odoo_port = 80
        odoo_url += '/hr/rfid/event'

        if self.module_username is False:
            username = ''
        else:
            username = str(self.module_username)

        if self.module_password is False:
            password = ''
        else:
            password = str(self.module_password)

        auth = base64.b64encode((username + ':' + password).encode())
        auth = auth.decode()
        req_headers = { "content-type": "application/json", "Authorization": "Basic " + str(auth) }
        host = str(self.last_ip)
        js_uart_conf = json.dumps([
            {
                "br": 9600,
                "db": 3,
                "fc": 0,
                "ft": 122,
                "port": 0,
                "pr": 0,
                "rt": False,
                "sb": 1,
                "usage": 0
            }, {
                "br": 9600,
                "db": 3,
                "fc": 0,
                "ft": 122,
                "port": 2,
                "pr": 0,
                "rt": False,
                "sb": 1,
                "usage": 1
            }
        ])

        config_params = 'sdk=1&stsd=1&sdts=1&stsu=' + odoo_url + '&prt=' \
                        + str(odoo_port) + '&hb=1&thb=60&br=1&odoo=1'
        try:
            conn = http.client.HTTPConnection(str(host), 80, timeout=2)
            conn.request("POST", "/protect/uart/conf", js_uart_conf, req_headers)
            response = conn.getresponse()
            conn.close()
            code = response.getcode()
            body = response.read()
            if code != 200:
                raise exceptions.ValidationError('While trying to setup /protect/uart/conf the module '
                                                 'returned code ' + str(code) + ' with body:\n' +
                                                 body.decode())

            conn = http.client.HTTPConnection(str(host), 80, timeout=2)
            conn.request("POST", "/protect/config.htm", config_params, req_headers)
            response = conn.getresponse()
            conn.close()
            code = response.getcode()
            body = response.read()
            if code != 200:
                raise exceptions.ValidationError('While trying to setup /protect/config.htm the module '
                                                 'returned code ' + str(code) + ' with body:\n' +
                                                 body.decode())
        except socket.timeout:
            raise exceptions.ValidationError('Could not connect to the module. '
                                             "Check if it is turned on or if it's on a different ip.")
        except (socket.error, socket.gaierror, socket.herror) as e:
            raise exceptions.ValidationError('Error while trying to connect to the module.'
                                             ' Information:\n' + str(e))

    @api.one
    def action_check_if_ws_available(self):
        host = str(self.last_ip)
        try:
            conn = http.client.HTTPConnection(str(host), 80, timeout=2)
            conn.request("GET", "/config.json")
            response = conn.getresponse()
            code = response.getcode()
            body = response.read()
            conn.close()
            if code != 200:
                raise exceptions.ValidationError('Webstack sent us http code {}'
                                                 ' when 200 was expected.'.format(code))

            js = json.loads(body.decode())
            module = {
                'version': js['sdk']['sdkVersion'],
                'hw_version': js['sdk']['sdkHardware'],
                'serial': js['convertor'],
                'available': 'a',
            }
            self.write(module)
        except socket.timeout:
            raise exceptions.ValidationError('Could not connect to the webstack')
        except(socket.error, socket.gaierror, socket.herror) as e:
            raise exceptions.ValidationError('Unexpected error:\n' + str(e))
        except KeyError as __:
            raise exceptions.ValidationError('Information returned by the webstack invalid')

    @api.one
    def action_set_active(self):
        self.ws_active = True

    @api.one
    def action_set_inactive(self):
        self.ws_active = False

    ##################################################################################
    ### All the functions bellow change data beyond this model, use them carefully ###
    ##################################################################################

    @api.multi
    def deal_with_event(self, post, last_ip):
        self.ensure_one()

        if not self.ws_active:
            ret = { 'status': 400 }
        elif 'heartbeat' in post:
            ret = self.parse_heartbeat(post)
        elif 'event' in post:
            ret = self.parse_event(post)
        elif 'response' in post:
            ret = self.parse_response(post)
        else:
            self.report_sys_ev(post, 'Webstack did not sent us a proper event.')
            ret = { 'status': 400 }

        self.write({
            'last_ip': last_ip,
            'updated_at': fields.Datetime.now(),
        })
        return ret

    @api.multi
    def check_for_unsent_cmd(self, status_code=200, event=None):
        self.ensure_one()
        commands_env = self.env['hr.rfid.command']

        processing_comm = commands_env.search([
            ('webstack_id', '=', self.id),
            ('status', '=', 'Process'),
        ])

        if processing_comm:
            processing_comm = processing_comm[-1]
            return self.retry_command(processing_comm, status_code, event)

        command = commands_env.search([
            ('webstack_id', '=', self.id),
            ('status', '=', 'Wait'),
        ])

        if not command:
            return { 'status': status_code }

        command = command[-1]

        if event is not None:
            event.command_id = command
        return self.send_command(command, status_code)

    @api.multi
    def retry_command(self, cmd, status_code=200, event=None):
        self.ensure_one()
        if cmd.retries == 5:
            cmd.status = 'Failure'
            return self.check_for_unsent_cmd(status_code, event)

        cmd.retries = cmd.retries + 1

        if event is not None:
            event.command_id = cmd
        return self.send_command(cmd, status_code)

    @api.multi
    def send_command(self, cmd, status_code=200):
        self.ensure_one()

        cmd.status = 'Process'

        json_cmd = {
            'status': status_code,
            'cmd': {
                'id': cmd.controller_id.ctrl_id,
                'c': cmd.cmd[:2],
                'd': cmd.cmd_data,
            }
        }

        if cmd.cmd == 'D1':
            card_num = ''.join(list('0' + ch for ch in cmd.card_number))
            pin_code = ''.join(list('0' + ch for ch in cmd.pin_code))
            ts_code = str(cmd.ts_code)
            rights_data = '{:02X}'.format(cmd.rights_data)
            rights_mask = '{:02X}'.format(cmd.rights_mask)

            json_cmd['cmd']['d'] = card_num + pin_code + ts_code + rights_data + rights_mask

        if cmd.cmd == 'D7':
            dt = datetime.now()
            dt += self._get_tz_offset()

            json_cmd['cmd']['d'] = '{:02}{:02}{:02}{:02}{:02}{:02}{:02}'.format(
                dt.second, dt.minute, dt.hour, dt.weekday() + 1, dt.day, dt.month, dt.year % 100
            )

        cmd.request = json.dumps(json_cmd)

        return json_cmd

    @api.multi
    def parse_heartbeat(self, post):
        self.ensure_one()
        self.version = str(post['FW'])
        return self.check_for_unsent_cmd(200)

    @api.multi
    def parse_event(self, post):
        self.ensure_one()
        controller = self.controllers.filtered(lambda r: r.ctrl_id == post['event']['id'])
        vending_hw_version = '16'

        if not controller:
            ctrl_env = self.env['hr.rfid.ctrl']
            cmd_env = self.env['hr.rfid.command']

            controller = ctrl_env.create({
                'name': 'Controller',
                'ctrl_id': post['event']['id'],
                'webstack_id': self.id,
            })

            command = cmd_env.create({
                'webstack_id': self.id,
                'controller_id': controller.id,
                'cmd': 'F0',
            })

            return self.send_command(command, 400)

        card_env = self.env['hr.rfid.card'].sudo()
        workcodes_env = self.env['hr.rfid.workcode'].sudo()
        reader = None
        event_action = post['event']['event_n']

        # Power on event
        if event_action == 30:
            cmd_env = self.env['hr.rfid.command'].sudo()
            self.report_sys_ev('Controller restarted', controller)
            cmd = cmd_env.create({
                'webstack_id': self.id,
                'controller_id': controller.id,
                'cmd': 'D7',
            })
            return self.send_command(cmd, 200)

        card = card_env.search([ ('number', '=', post['event']['card']) ])

        reader_num = post['event']['reader']
        if reader_num == 0:
            reader_num = ((post['event']['event_n'] - 3) % 4) + 1
        else:
            reader_num = reader_num & 0x07
        for it in controller.reader_ids:
            if it.number == reader_num:
                reader = it
                break

        if reader is None:
            self.report_sys_ev('Could not find a reader with that id', controller)
            return self.check_for_unsent_cmd(200)

        ev_env = self.env['hr.rfid.event.user'].sudo()

        if not card:
            if event_action == 64 and controller.hw_version != vending_hw_version:
                cmd_env = self.env['hr.rfid.command'].sudo()
                cmd = {
                    'webstack_id': self.id,
                    'controller_id': controller.id,
                    'cmd': 'DB',
                    'status': 'Process',
                    'ex_timestamp': fields.Datetime.now(),
                    'cmd_data': '40%02X00' % (4 + 4*(reader.number - 1)),
                }
                cmd = cmd_env.create(cmd)
                self.report_sys_ev('Could not find the card', controller)
                return self.send_command(cmd, 200)
            elif event_action in [ 21, 22, 23, 24 ]:
                event_dict = {
                    'ctrl_addr': controller.ctrl_id,
                    'door_id': reader.door_id.id,
                    'reader_id': reader.id,
                    'event_time': self.get_ws_time_str(post),
                    'event_action': '5',  # Exit button
                }
                event = ev_env.create(event_dict)
                return self.check_for_unsent_cmd(200, event)

            self.report_sys_ev('Could not find the card', controller)
            return self.check_for_unsent_cmd(200)

        # External db event, controller requests for permission to open or close door
        if event_action == 64 and controller.hw_version != vending_hw_version:
            ret = self.env['hr.rfid.access.group.door.rel'].sudo().search([
                ('access_group_id', 'in', card.get_owner().hr_rfid_access_group_ids.ids),
                ('door_id', '=', reader.door_id.id)
            ])
            return self.respond_to_ev_64(post, ret and card.card_active is True, controller, reader, card)

        # Turnstile controller. If the 7th bit is not up, then there was no actual entry
        if controller.hw_version == '9' and (post['event']['reader'] & 64) == 0:
            event_action = 6
        else:
            event_action = ((event_action - 3) % 4) + 1

        event_dict = {
            'ctrl_addr': controller.ctrl_id,
            'door_id': reader.door_id.id,
            'reader_id': reader.id,
            'card_id': card.id,
            'event_time': self.get_ws_time_str(post),
            'event_action': str(event_action),
        }

        # Card and workcode
        if reader.mode == '03' and controller.hw_version != vending_hw_version:
            wc = workcodes_env.search([
                ('workcode', '=', post['event']['dt'])
            ])
            if not wc:
                event_dict['workcode'] = post['event']['dt']
            else:
                event_dict['workcode_id'] = wc.id

        self._get_card_owner(event_dict, card)
        event = ev_env.create(event_dict)

        return self.check_for_unsent_cmd(200, event)

    @api.multi
    def parse_response(self, post):
        self.ensure_one()
        command_env = self.env['hr.rfid.command'].sudo()
        response = post['response']
        controller = None

        for ctrl in self.controllers:
            if ctrl.ctrl_id == response['id']:
                controller = ctrl
                break

        if controller is None:
            self.report_sys_ev('Module sent us a response from a controller that does not exist')
            return self.check_for_unsent_cmd(200)

        command = command_env.search([ ('webstack_id', '=', self.id),
                                       ('controller_id', '=', controller.id),
                                       ('status', '=', 'Process'),
                                       ('cmd', '=', response['c']), ], limit=1)

        if not command and response['c'] == 'DB':
            command = command_env.search([ ('webstack_id', '=', self.id),
                                           ('controller_id', '=', controller.id),
                                           ('status', '=', 'Process'),
                                           ('cmd', '=', 'DB2'), ], limit=1)

        if not command:
            self.report_sys_ev('Controller sent us a response to a command we never sent')
            return self.check_for_unsent_cmd(200)

        if response['e'] != 0:
            command.write({
                'status': 'Failure',
                'error': str(response['e']),
                'ex_timestamp': fields.datetime.now(),
                'response': json.dumps(post),
            })
            return self.check_for_unsent_cmd(200)

        if response['c'] == 'F0':
            self.parse_response_f0(post, command, controller)

        if response['c'] == 'F6':
            self.parse_response_f6(post, controller)

        if response['c'] == 'F9':
            self.parse_response_f9(post, controller)

        command.write({
            'status': 'Success',
            'ex_timestamp': fields.datetime.now(),
            'response': json.dumps(post),
        })

        return self.check_for_unsent_cmd(200)

    @api.multi
    def parse_response_f0(self, post, command, controller):
        self.ensure_one()
        response = post['response']
        data = response['d']
        vending_hw_version = '16'

        ctrl_mode = int(data[42:44], 16)
        external_db = ctrl_mode & 0x20 > 0
        ctrl_mode = ctrl_mode & 0x0F

        if ctrl_mode < 1 or ctrl_mode > 4:
            return self.log_cmd_error(post, 'F0 command failure, controller sent us a wrong mode',
                                      command, '31', 200)

        readers_count = int(data[30:32], 16)

        mode_reader_relation = { 1: [2], 2: [2, 4], 3: [4], 4: [4] }

        if readers_count not in mode_reader_relation[ctrl_mode]:
            return self.log_cmd_error(post, 'F0 sent us a wrong reader-controller mode combination',
                                      command, '31', 200)

        reader_env = self.env['hr.rfid.reader'].sudo()
        door_env = self.env['hr.rfid.door'].sudo()
        ctrl_env = self.env['hr.rfid.ctrl'].sudo()

        def bytes_to_num(start, digits):
            digits = digits-1
            res = 0
            for j in range(digits+1):
                multiplier = 10 ** (digits-j)
                res = res + int(data[start:start+2], 16) * multiplier
                start = start + 2
            return res

        hw_ver = str(bytes_to_num(0, 2))
        serial_num = str(bytes_to_num(4, 4))
        sw_ver = str(bytes_to_num(12, 3))
        inputs = bytes_to_num(18, 3)
        outputs = bytes_to_num(24, 3)
        time_schedules = bytes_to_num(32, 2)
        io_table_lines = bytes_to_num(36, 2)
        alarm_lines = bytes_to_num(40, 1)
        max_cards_count = bytes_to_num(44, 5)
        max_events_count = bytes_to_num(54, 5)

        old_ctrl = ctrl_env.search([
            ('serial_number', '=', serial_num)
        ], limit=1)

        if old_ctrl:
            old_ctrl.webstack_id = controller.webstack_id
            controller.unlink()
            return self.check_for_unsent_cmd(200)

        if controller.reader_ids:
            controller.reader_ids.unlink()

        if controller.door_ids:
            controller.door_ids.unlink()

        def create_door(name, number, ctrl_id):
            # If the controller is a vending controller
            if hw_ver == vending_hw_version:
                return None
            return door_env.create({
                'name': name,
                'number': number,
                'controller_id': ctrl_id,
            }).id

        def create_reader(name, number, reader_type, ctrl_id, door_id):
            create_dict = {
                'name': name,
                'number': number,
                'reader_type': reader_type,
                'controller_id': ctrl_id,
            }

            if door_id is not None:
                create_dict['door_id'] = door_id

            reader_env.create(create_dict)

        def gen_d_name(door_num, controller_id):
            return 'Door ' + str(door_num) + ' of ctrl ' + str(controller_id)

        if ctrl_mode == 1 or ctrl_mode == 3:
            last_door = create_door(gen_d_name(1, controller.id), 1, controller.id)
            create_reader('R1', 1, '0', controller.id, last_door)
            create_reader('R2', 2, '1', controller.id, last_door)
        elif ctrl_mode == 2 and readers_count == 4:
            last_door = create_door(gen_d_name(1, controller.id), 1, controller.id)
            create_reader('R1', 1, '0', controller.id, last_door)
            create_reader('R2', 2, '1', controller.id, last_door)
            last_door = create_door(gen_d_name(2, controller.id), 2, controller.id)
            create_reader('R3', 3, '0', controller.id, last_door)
            create_reader('R4', 4, '1', controller.id, last_door)
        else:  # (ctrl_mode == 2 and readers_count == 2) or ctrl_mode == 4
            last_door = create_door(gen_d_name(1, controller.id), 1, controller.id)
            create_reader('R1', 1, '0', controller.id, last_door)
            last_door = create_door(gen_d_name(2, controller.id), 2, controller.id)
            create_reader('R2', 2, '0', controller.id, last_door)

        if ctrl_mode == 3:
            last_door = create_door(gen_d_name(2, controller.id), 2, controller.id)
            create_reader('R3', 3, '0', controller.id, last_door)
            last_door = create_door(gen_d_name(3, controller.id), 3, controller.id)
            create_reader('R4', 4, '0', controller.id, last_door)
        elif ctrl_mode == 4:
            last_door = create_door(gen_d_name(3, controller.id), 3, controller.id)
            create_reader('R3', 3, '0', controller.id, last_door)
            last_door = create_door(gen_d_name(4, controller.id), 4, controller.id)
            create_reader('R4', 4, '0', controller.id, last_door)

        controller.write({
            'name': 'Controller ' + serial_num + ' ' + str(controller.ctrl_id),
            'hw_version': hw_ver,
            'serial_number': serial_num,
            'sw_version': sw_ver,
            'inputs': inputs,
            'outputs': outputs,
            'readers': readers_count,
            'time_schedules': time_schedules,
            'io_table_lines': io_table_lines,
            'alarm_lines': alarm_lines,
            'mode': ctrl_mode,
            'external_db': external_db,
            'max_cards_count': max_cards_count,
            'max_events_count': max_events_count,
        })

        cmd_env = self.env['hr.rfid.command'].sudo()
        cmd_env.create({
            'webstack_id': self.id,
            'controller_id': controller.id,
            'cmd': 'D7',
        })

        cmd_env.create({
            'webstack_id': self.id,
            'controller_id': controller.id,
            'cmd': 'DC',
            'cmd_data': '0303',
        })

        cmd_env.create({
            'webstack_id': self.id,
            'controller_id': controller.id,
            'cmd': 'DC',
            'cmd_data': '0404',
        })

        cmd_env.create({
            'webstack_id': self.id,
            'controller_id': controller.id,
            'cmd': 'F6',
        })

        cmd_env.create({
            'webstack_id': self.id,
            'controller_id': controller.id,
            'cmd': 'F9',
            'cmd_data': '00'
        })

    @api.multi
    def parse_response_f6(self, post, controller):
        self.ensure_one()
        response = post['response']
        data = response['d']
        readers = [None, None, None, None]
        for it in controller.reader_ids:
            readers[it.number-1] = it
        for i in range(4):
            if readers[i] is not None:
                mode = str(data[i*6:i*6+2])
                readers[i].write({
                    'mode': mode,
                    'no_d6_cmd': True,
                })

    @api.multi
    def parse_response_f9(self, post, controller):
        self.ensure_one()
        response = post['response']
        controller.write({
            'io_table': response['d']
        })

    @api.multi
    def report_sys_ev(self, post, description, controller=None):
        self.ensure_one()
        sys_ev_env = self.env['hr.rfid.event.system'].sudo()

        sys_ev = {
            'webstack_id': self.id,
            'timestamp': self.get_ws_time_str(post),
            'error_description': description,
            'input_js': json.dumps(post),
        }
        if 'event' in post and 'event_n' in post['event']:
            sys_ev['event_action'] = str(post['event']['event_n']),
        if controller is not None:
            sys_ev['controller_id'] = controller.id

        sys_ev_env.create(sys_ev)

    @api.multi
    def respond_to_ev_64(self, post, open_door: bool, controller, reader, card):
        self.ensure_one()
        cmd_env = self.env['hr.rfid.command'].sudo()
        ev_env = self.env['hr.rfid.event.user'].sudo()
        open_door = 3 if open_door is True else 4
        cmd = {
            'webstack_id': self.id,
            'controller_id': controller.id,
            'cmd': 'DB',
            'status': 'Process',
            'ex_timestamp': fields.Datetime.now(),
            'cmd_data': '40%02X00' % (open_door + 4*(reader.number - 1)),
        }
        event = {
            'ctrl_addr': controller.ctrl_id,
            'door_id': reader.door_id.id,
            'reader_id': reader.id,
            'card_id': card.id,
            'event_time': self.get_ws_time_str(post),
            'event_action': '64',
        }
        self._get_card_owner(event, card)
        cmd = cmd_env.create(cmd)
        event['command_id'] = cmd.id
        ev_env.create(event)
        return self.send_command(cmd, 200)

    @api.multi
    def log_cmd_error(self, post, description, command, error, status_code):
        self.ensure_one()
        command.write({
            'status': 'Failure',
            'error': error,
            'ex_timestamp': fields.datetime.now(),
            'response': json.dumps(post),
        })

        self.report_sys_ev(post, description, command.controller_id)
        return self.check_for_unsent_cmd(status_code)

    @api.multi
    def get_ws_time_str(self, post):
        self.ensure_one()
        return self.get_ws_time(post).strftime('%m.%d.%y %H:%M:%S')

    @api.multi
    def get_ws_time(self, post):
        self.ensure_one()
        time = post['event']['date'] + ' ' + post['event']['time']
        time = datetime.strptime(time, '%m.%d.%y %H:%M:%S')
        time -= self._get_tz_offset()
        return time

    @staticmethod
    def _get_card_owner(event_dict: dict, card):
        if not card.employee_id:
            event_dict['contact_id'] = card.contact_id.id
        else:
            event_dict['employee_id'] = card.employee_id.id

    #################################################################################
    ### All the functions above change data beyond this model, use them carefully ###
    #################################################################################

    @api.depends('tz')
    def _compute_tz_offset(self):
        for user in self:
            user.tz_offset = datetime.now(pytz.timezone(user.tz or 'GMT')).strftime('%z')

    @api.multi
    def _compute_http_link(self):
        for record in self:
            if record.last_ip != '' and record.last_ip is not False:
                link = 'http://' + record.last_ip + '/'
                record.http_link = link
            else:
                record.http_link = ''

    @api.model
    def _deconfirm_webstack(self, ws):
        ws.available = 'u'

    @api.model
    def _confirm_webstack(self, ws):
        ws.available = 'c'

    @api.multi
    def _get_tz_offset(self):
        self.ensure_one()
        tz_h = int(self.tz_offset[:3], 10)
        tz_m = int(self.tz_offset[3:], 10)
        return timedelta(hours=tz_h, minutes=tz_m)

    @api.multi
    def write(self, vals):
        if 'tz' not in vals:
            return super(HrRfidWebstack, self).write(vals)

        commands_env = self.env['hr.rfid.command']

        for ws in self:
            old_tz = ws.tz
            super(HrRfidWebstack, ws).write(vals)
            new_tz = ws.tz

            if old_tz != new_tz:
                for ctrl in ws.controllers:
                    commands_env.create([{
                        'webstack_id': ctrl.webstack_id.id,
                        'controller_id': ctrl.id,
                        'cmd': 'D7',
                    }])


class HrRfidCtrlIoTableRow(models.TransientModel):
    _name = 'hr.rfid.ctrl.io.table.row'
    _description = 'Controller IO Table row'

    event_codes = [
        ('1' , "Duress"),
        ('2' , "Duress Error"),
        ('3' , "Reader #1 Card OK"),
        ('4' , "Reader #1 Card Error"),
        ('5' , "Reader #1 TS Error"),
        ('6' , "Reader #1 APB Error"),
        ('7' , "Reader #2 Card OK"),
        ('8' , "Reader #2 Card Error"),
        ('9' , "Reader #2 TS Error"),
        ('10', "Reader #2 APB Error"),
        ('11', "Reader #3 Card OK"),
        ('12', "Reader #3 Card Error"),
        ('13', "Reader #3 TS Error"),
        ('14', "Reader #3 APB Error"),
        ('15', "Reader #4 Card OK"),
        ('16', "Reader #4 Card Error"),
        ('17', "Reader #4 TS Error"),
        ('18', "Reader #4 APB Error"),
        ('19', "Emergency Input"),
        ('20', "Arm On Siren"),
        ('21', "Exit Button 1"),
        ('22', "Exit Button 2"),
        ('23', "Exit Button 3"),
        ('24', "Exit Button 4"),
        ('25', "Door Overtime"),
        ('26', "Door Forced Open"),
        ('27', "On Delay"),
        ('28', "Off Delay"),
    ]

    event_number = fields.Selection(
        selection=event_codes,
        string='Event Number',
        help='What the outs are set to when this event occurs',
        required=True,
        readonly=True,
    )

    # Range is from 00 to 99
    out8 = fields.Integer(string='Out8', required=True)
    out7 = fields.Integer(string='Out7', required=True)
    out6 = fields.Integer(string='Out6', required=True)
    out5 = fields.Integer(string='Out5', required=True)
    out4 = fields.Integer(string='Out4', required=True)
    out3 = fields.Integer(string='Out3', required=True)
    out2 = fields.Integer(string='Out2', required=True)
    out1 = fields.Integer(string='Out1', required=True)


class HrRfidCtrlIoTableWiz(models.TransientModel):
    _name = 'hr.rfid.ctrl.io.table.wiz'
    _description = 'Controller IO Table Wizard'

    def _default_ctrl(self):
        return self.env['hr.rfid.ctrl'].browse(self._context.get('active_ids'))

    def _generate_io_table(self):
        rows_env = self.env['hr.rfid.ctrl.io.table.row']
        row_len = 8 * 2  # 8 outs, 2 symbols each to display the number
        ctrl = self._default_ctrl()

        if len(ctrl.io_table) % row_len != 0:
            raise exceptions.ValidationError('Controller does now have an input/output table loaded!')

        io_table = ctrl.io_table
        rows = rows_env

        for i in range(0, len(ctrl.io_table), row_len):
            creation_dict = { 'event_number': str(int(i / row_len) + 1) }
            for j in range(8, 0, -1):
                index = i + ((8 - j) * 2)
                creation_dict['out' + str(j)] = int(io_table[index:index+2], 16)
            rows += rows_env.create(creation_dict)

        return rows

    def _default_outs(self):
        return self._default_ctrl().outputs

    controller_id = fields.Many2one(
        'hr.rfid.ctrl',
        default=_default_ctrl,
        required=True
    )

    io_row_ids = fields.Many2many(
        'hr.rfid.ctrl.io.table.row',
        string='IO Table',
        default=_generate_io_table,
    )

    outs = fields.Integer(
        default=_default_outs,
    )

    @api.multi
    def save_table(self):
        self.ensure_one()

        new_io_table = ''

        for row in self.io_row_ids:
            outs = [ row.out8, row.out7, row.out6, row.out5, row.out4, row.out3, row.out2, row.out1 ]
            for out in outs:
                if out < 0 or out > 99:
                    raise exceptions.ValidationError(
                        _('%d is not a valid number for the io table. Valid values range from 0 to 99') % out
                    )
                new_io_table += '%02X' % out

        self.controller_id.change_io_table(new_io_table)


class HrRfidController(models.Model):
    _name = 'hr.rfid.ctrl'
    _inherit = ['mail.thread']
    _description = 'Controller'
    _sql_constraints = [ ('rfid_controller_unique', 'unique(serial_number)',
                          'Serial numbers must be unique!') ]

    hw_types = [ ('1', 'iCON200'), ('2', 'iCON150'), ('3', 'iCON150'), ('4', 'iCON140'),
                 ('5', 'iCON120'), ('6', 'iCON110'), ('7', 'iCON160'), ('8', 'iCON170'),
                 ('9', 'Turnstile'), ('10', 'iCON180'), ('11', 'iCON115'), ('12', 'iCON50'),
                 ('13', 'FireControl'), ('14', 'FireControl'), ('18', 'FireControl'),
                 ('19', 'FireControl'), ('15', 'TempRH'), ('16', 'Vending'), ('17', 'iCON130'),
                 ('20', 'AlarmControl'), ('21', 'AlarmControl'), ('22', 'AlarmControl'),
                 ('23', 'AlarmControl'), ('26', 'AlarmControl'), ('27', 'AlarmControl'),
                 ('28', 'AlarmControl'), ('29', 'AlarmControl'), ('24', 'iTemp'), ('25', 'iGas'),
                 ('30', 'RelayControl110'), ('31', 'RelayControl150'), ('32', 'RelayControl'),
                 ('33', 'RelayControl'), ('34', 'RelayControl'), ('35', 'RelayControl'),
                 ('36', 'RelayControl'), ('37', 'RelayControl'), ('38', 'RelayControl'),
                 ('39', 'RelayControl'), ('40', 'MFReader'), ('41', 'MFReader'), ('42', 'MFReader'),
                 ('43', 'MFReader'), ('44', 'MFReader'), ('45', 'MFReader'), ('46', 'MFReader'),
                 ('47', 'MFReader'), ('48', 'MFReader'), ('49', 'MFReader'), ('50', 'iMotor') ]

    name = fields.Char(
        string='Name',
        help='Label to easily distinguish the controller',
        required=True,
        index=True,
        track_visibility='onchange',
    )

    ctrl_id = fields.Integer(
        string='ID',
        help='A number to distinguish the controller from others on the same module',
        index=True,
    )

    hw_version = fields.Selection(
        selection=hw_types,
        string='Hardware Type',
        help='Type of the controller',
    )

    serial_number = fields.Char(
        string='Serial',
        help='Serial number of the controller',
        limit=4,
    )

    sw_version = fields.Char(
        string='Version',
        help='The version of the software on the controller',
        limit=3,
    )

    inputs = fields.Integer(
        string='Inputs',
        help='Mask describing the inputs of the controller',
    )

    outputs = fields.Integer(
        string='Outputs',
        help='Mask detailing the outputs of the controller',
    )

    readers = fields.Integer(
        string='Readers',
        help='Number of readers on the controller'
    )

    time_schedules = fields.Integer(
        string='Time Schedules',
        help='',
    )

    io_table_lines = fields.Integer(
        string='IO Table Lines',
        help='Size of the input/output table',
    )

    alarm_lines = fields.Integer(
        string='Alarm Lines',
        help='How many alarm inputs there are',
    )

    mode = fields.Integer(
        string='Controller Mode',
        help='The mode of the controller',
    )

    external_db = fields.Boolean(
        string='External DB',
        help='If the controller uses the "ExternalDB" feature.',
        default=False,
    )

    max_cards_count = fields.Integer(
        string='Maximum Cards',
        help='Maximum amount of cards the controller can hold in memory',
    )

    max_events_count = fields.Integer(
        string='Maximum Events',
        help='Maximum amount of events the controller can hold in memory',
    )

    # Warning, don't change this field manually unless you know how to create a
    # command to change the io table for the controller or are looking to avoid exactly that.
    # You can use the change_io_table method to automatically create a command
    io_table = fields.Char(
        string='Input/Output Table',
        help='Input and output table for the controller.',
    )

    webstack_id = fields.Many2one(
        'hr.rfid.webstack',
        string='Module',
        help='Module the controller serves',
        required=True,
        readonly=True,
        ondelete='cascade',
    )

    door_ids = fields.One2many(
        'hr.rfid.door',
        'controller_id',
        string='Controlled Doors',
        help='Doors that belong to this controller'
    )

    reader_ids = fields.One2many(
        'hr.rfid.reader',
        'controller_id',
        string='Controlled Readers',
        help='Readers that belong to this controller',
    )

    system_event_ids = fields.One2many(
        'hr.rfid.event.system',
        'controller_id',
        string='Errors',
        help='Errors received from the controller',
    )

    command_ids = fields.One2many(
        'hr.rfid.command',
        'controller_id',
        string='Commands',
        help='Commands that have been sent to this controller',
    )

    @api.model
    def get_default_io_table(self, hw_type, sw_version, mode):
        io_tables = {
            # iCON110
            '6': {
                1: [
                    (734, '0000000000000000000000000000000000000000000000030000000000000300000000000000030000000000000003000000000000000003000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000040463000000000000030000000000000000030000000000000000000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000000300'),
                ],
                2: [
                    (734, '0000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000046363000000000000030000000000000000030000000000000000000000000000030000000000000003000000000000000000000000000000000000000000000003000000000000000300'),
                ],
            },
            # Turnstile
            '9': {
                1: [
                    (734, '0000000003030303050505050000000000000000000000030000000300000000000000030000000000000003000000000000000000000300000003000000000000000300000000000000030000000000000000000003000000030000000000000003000000000000000300000000000000000000030000000300000000000000030000000000000003000000000000000000000063636363000000000000000000000000000000030000000000000300000000000003000000000000030000000404040401010101040404040000000000000000000000000000000000000000'),
                    (740, '0000000003030303050505050000000000000000000000030000000300000000000000030000000000000003000000000000000000000300000003000000000000000300000000000000030000000000000000000003000000030000000000000003000000000000000300000000000000000000030000000300000000000000030000000000000003000000000000000000000063636363000000000305030500000000000000030000000000000300000000000003000000000000030000000404040401010101040404040000000000000000000000000000000000000000'),
                ]
            },
            # iCON115
            '11': {
                1: [
                    (734, '0000000000000000000000000000000000000000000000030000000000000300000000000000030000000000000003000000000000000003000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000006363000000000000000000000000000000030000000000000000000000000000030000000000000003000000000000000300000000000000030000000000000000000000000000000000'),
                ],
                2: [
                    (734, '0000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000006363000000000000000000000000000000030000000000000000000000000000030000000000000003000000000000000000000000000000000000000000000000000000000000000000'),
                ],
            },
            # iCON50
            '12': {
                1: [
                    (734, '0000000000000003000000000000030000000000000000030000000000000300000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
                ],
            },
            # iCON130
            '17': {
                2: [
                    (734, '0000000000000303000005050000000000000000000000030000000300000000000000030000000000000003000000000000000000000003000000030000000000000003000000000000000300000000000000000003000000000300000000000000030000000000000003000000000000000000000300000000030000000000000003000000000000000300000000000000000000006363000000000000000000000000000000030000000000000300000000000000000000000000000000000000010100000303000001010000030300000000000000000000000000000000'),
                ],
                3: [
                    (734, '0000000000030303000505050000000000000000000000030000000300000000000000030000000000000003000000000000000000000003000000030000000000000003000000000000000300000000000000000003000000000300000000000000030000000000000003000000000000000000030000000003000000000000000300000000000000030000000000000000000000636363000000000000000000000000000000030000000000000300000000000003000000000000000000000001010100030303000101010003030300000000000000000000000000000000'),
                ],
                4: [
                    (734, '0000000003030303050505050000000000000000000000030000000300000000000000030000000000000003000000000000000000000300000003000000000000000300000000000000030000000000000000000003000000030000000000000003000000000000000300000000000000000000030000000300000000000000030000000000000003000000000000000000000063636363000000000000000000000000000000030000000000000300000000000003000000000000030000000101010103030303010101010303030300000000000000000000000000000000'),
                ],
            },
        }

        if hw_type not in io_tables or mode not in io_tables[hw_type]:
            return ''

        sw_versions = io_tables[hw_type][mode]
        io_table = ''
        for sw_v, io_t in sw_versions:
            if int(sw_version) > sw_v:
                io_table = io_t
        return io_table

    @api.one
    def button_reload_cards(self):
        cmd_env = self.env['hr.rfid.command'].sudo()

        cmd_env.create({
            'webstack_id': self.webstack_id.id,
            'controller_id': self.id,
            'cmd': 'DC',
            'cmd_data': '0303',
        })

        cmd_env.create({
            'webstack_id': self.webstack_id.id,
            'controller_id': self.id,
            'cmd': 'DC',
            'cmd_data': '0404',
        })

        for door in self.door_ids:
            door.card_rel_ids.unlink()
            self.env['hr.rfid.card.door.rel'].update_door_rels(door)

    @api.multi
    def change_io_table(self, new_io_table):
        cmd_env = self.env['hr.rfid.command'].sudo()
        cmd_data = '00' + new_io_table

        for ctrl in self:
            if ctrl.io_table == new_io_table:
                continue

            if len(ctrl.io_table) != len(new_io_table):
                raise exceptions.ValidationError(
                    'Io table lengths are different, this should never happen????'
                )

            ctrl.io_table = new_io_table
            cmd_env.create({
                'webstack_id': ctrl.webstack_id.id,
                'controller_id': ctrl.id,
                'cmd': 'D9',
                'cmd_data': cmd_data,
            })

    @api.multi
    def write(self, vals):
        # TODO Check if mode is being changed, change io table if so
        cmd_env = self.env['hr.rfid.command'].sudo()
        for ctrl in self:
            old_ext_db = ctrl.external_db
            super(HrRfidController, ctrl).write(vals)
            new_ext_db = ctrl.external_db

            if old_ext_db != new_ext_db:
                cmd_dict = {
                    'webstack_id': ctrl.webstack_id.id,
                    'controller_id': ctrl.id,
                    'cmd': 'D5',
                }
                if new_ext_db is True:
                    new_mode = 0x20 + ctrl.mode
                    cmd_dict['cmd_data'] = '%02X' % new_mode
                else:
                    cmd_dict['cmd_data'] = '%02X' % ctrl.mode
                cmd_env.create(cmd_dict)


class HrRfidDoorOpenCloseWiz(models.TransientModel):
    _name = 'hr.rfid.door.open.close.wiz'
    _description = 'Open or close door'

    def _default_doors(self):
        return self.env['hr.rfid.door'].browse(self._context.get('active_ids'))

    doors = fields.Many2many(
        'hr.rfid.door',
        string='Doors to open/close',
        required=True,
        default=_default_doors,
    )

    time = fields.Integer(
        string='Time',
        help='Amount of time (in seconds) the doors will stay open or closed. 0 for infinity.',
        default=3,
        required=True,
    )

    @api.multi
    def open_doors(self):
        for door in self.doors:
            door.open_close_door(out=1, time=self.time)
        return create_and_ret_d_box(self.env, 'Doors opened', 'Doors successfully opened')

    @api.multi
    def close_doors(self):
        for door in self.doors:
            door.open_close_door(out=0, time=self.time)
        return create_and_ret_d_box(self.env, 'Door closed', 'Doors successfully closed')


class HrRfidDoor(models.Model):
    _name = 'hr.rfid.door'
    _description = 'Door'
    _inherit = ['mail.thread']

    name = fields.Char(
        string='Name',
        help='A label to easily differentiate doors',
        required=True,
        intex=True,
        track_visibility='onchange',
    )

    number = fields.Integer(
        string='Number',
        help='Number of the door in the controller',
        required=True,
        index=True,
    )

    card_type = fields.Many2one(
        'hr.rfid.card.type',
        string='Card type',
        help='Only cards of this type this door will open to',
        default=lambda self: self.env.ref('hr_rfid.hr_rfid_card_type_def').id,
        ondelete='set null',
        track_visibility='onchange',
    )

    controller_id = fields.Many2one(
        'hr.rfid.ctrl',
        string='Controller',
        help='Controller that manages the door',
        required=True,
        readonly=True,
        ondelete='cascade',
    )

    access_group_ids = fields.One2many(
        'hr.rfid.access.group.door.rel',
        'door_id',
        string='Door Access Groups',
        help='The access groups this door is a part of',
    )

    user_event_ids = fields.One2many(
        'hr.rfid.event.user',
        'door_id',
        string='Events',
        help='Events concerning this door',
    )

    reader_ids = fields.One2many(
        'hr.rfid.reader',
        'door_id',
        string='Readers',
        help='Readers that open this door',
    )

    card_rel_ids = fields.One2many(
        'hr.rfid.card.door.rel',
        'door_id',
        string='Cards',
        help='Cards that have access to this door',
    )

    def get_potential_cards(self, access_groups=None):
        """
        Returns a list of tuples (card, time_schedule) for which the card potentially has access to this door
        """
        if access_groups is None:
            acc_gr_rels = self.access_group_ids
        else:
            acc_gr_rels = self.env['hr.rfid.access.group.door.rel'].search([
                ('id', 'in', self.access_group_ids.ids),
                ('access_group_id', 'in', access_groups.ids),
            ])
        ret = []
        for rel in acc_gr_rels:
            ts_id = rel.time_schedule_id
            acc_gr = rel.access_group_id
            employees = acc_gr.mapped('all_employee_ids').mapped('employee_id')
            contacts = acc_gr.mapped('all_contact_ids').mapped('contact_id')
            cards = employees.mapped('hr_rfid_card_ids') + contacts.mapped('hr_rfid_card_ids')
            for card in cards:
                ret.append((card, ts_id))
        return ret

    @api.multi
    def open_door(self):
        self.ensure_one()
        return self.open_close_door(1, 3)

    @api.multi
    def close_door(self):
        self.ensure_one()
        return self.open_close_door(0, 3)

    @api.multi
    def open_close_door(self, out: int, time: int):
        self.ensure_one()

        if self.controller_id.webstack_id.behind_nat is True:
            self.create_door_out_cmd(out, time)
            return create_and_ret_d_box(self.env, _('Command creation successful'),
                                        _('Because the webstack is behind NAT, we have to wait for the '
                                          'webstack to call us, so we created a command. The door will '
                                          'open/close for %d seconds as soon as possible.') % time)
        else:
            self.change_door_out(out, time)
            return create_and_ret_d_box(self.env, _('Door successfully opened/closed'),
                                        _('Door will remain opened/closed for %d seconds.') % time)

    @api.multi
    def create_door_out_cmd(self, out: int, time: int):
        self.ensure_one()
        cmd_env = self.env['hr.rfid.command']
        cmd_env.create([{
            'webstack_id': self.controller_id.webstack_id.id,
            'controller_id': self.controller_id.id,
            'cmd': 'DB',
            'cmd_data': '%02d%02d%02d' % (self.number, out, time),
        }])
        self.log_door_change(out, time, cmd=True)

    @api.multi
    def change_door_out(self, out: int, time: int):
        """
        :param out: 0 to open door, 1 to close door
        :param time: Range: [0, 99]
        """
        self.ensure_one()
        self.log_door_change(out, time)

        ws = self.controller_id.webstack_id
        if ws.module_username is False:
            username = ''
        else:
            username = str(ws.module_username)

        if ws.module_password is False:
            password = ''
        else:
            password = str(ws.module_password)

        auth = base64.b64encode((username + ':' + password).encode())
        auth = auth.decode()
        headers = { 'content-type': 'application/json', 'Authorization': 'Basic ' + str(auth) }
        cmd = json.dumps({
            'cmd': {
                'id': self.controller_id.ctrl_id,
                'c': 'DB',
                'd': '%02d%02d%02d' % (self.number, out, time),
            }
        })

        host = str(ws.last_ip)
        try:
            conn = http.client.HTTPConnection(str(host), 80, timeout=2)
            conn.request('POST', '/sdk/cmd.json', cmd, headers)
            response = conn.getresponse()
            code = response.getcode()
            body = response.read()
            conn.close()
            if code != 200:
                raise exceptions.ValidationError('While trying to send the command to the module, '
                                                 'it returned code ' + str(code) + ' with body:\n'
                                                 + body.decode())

            body_js = json.loads(body.decode())
            if body_js['response']['e'] != 0:
                raise exceptions.ValidationError('Error. Controller returned body:\n' + body)
        except socket.timeout:
            raise exceptions.ValidationError('Could not connect to the module. '
                                             "Check if it is turned on or if it's on a different ip.")
        except (socket.error, socket.gaierror, socket.herror) as e:
            raise exceptions.ValidationError('Error while trying to connect to the module.'
                                             ' Information:\n' + str(e))

    @api.multi
    def log_door_change(self, action: int, time: int, cmd: bool = False):
        """
        :param action: 1 for door open, 0 for door close
        :param time: Range: [0, 99]
        :param cmd: If the command was created instead of
        """
        self.ensure_one()
        if time > 0:
            if cmd is False:
                if action == 1:
                    self.message_post(body=_('Opened the door for %d seconds.') % time)
                else:
                    self.message_post(body=_('Closed the door for %d seconds.') % time)
            else:
                if action == 1:
                    self.message_post(body=_('Created a command to open the door for %d seconds.') % time)
                else:
                    self.message_post(body=_('Created a command to close the door for %d seconds.') % time)
        else:
            if cmd is False:
                if action == 1:
                    self.message_post(body=_('Opened the door.') % time)
                else:
                    self.message_post(body=_('Closed the door.') % time)
            else:
                if action == 1:
                    self.message_post(body=_('Created a command to open the door.') % time)
                else:
                    self.message_post(body=_('Created a command to close the door.') % time)

    @api.multi
    def write(self, vals):
        rel_env = self.env['hr.rfid.card.door.rel']
        for door in self:
            old_card_type = door.card_type

            super(HrRfidDoor, door).write(vals)

            if old_card_type != door.card_type:
                rel_env.update_door_rels(door)

        return True


class HrRfidTimeSchedule(models.Model):
    _name = 'hr.rfid.time.schedule'
    _inherit = ['mail.thread']
    _description = 'Time Schedule'

    name = fields.Char(
        string='Name',
        help='Label for the time schedule',
        required=True,
        track_visibility='onchange',
    )

    number = fields.Integer(
        string='TS Number',
        required=True,
        readonly=True,
    )

    access_group_door_ids = fields.One2many(
        'hr.rfid.access.group.door.rel',
        'time_schedule_id',
        string='Access Group/Door Combinations',
        help='Which doors use this time schedule in which access group',
    )

    @api.multi
    def unlink(self):
        raise exceptions.ValidationError('Cannot delete time schedules!')


class HrRfidReader(models.Model):
    _name = 'hr.rfid.reader'
    _inherit = ['mail.thread']
    _description = 'Reader'

    reader_types = [
        ('0', 'In'),
        ('1', 'Out'),
    ]

    reader_modes = [
        ('01', 'Card Only'),
        ('02', 'Card and Pin'),
        ('03', 'Card and Workcode'),
        ('04', 'Card or Pin'),
    ]

    name = fields.Char(
        string='Reader name',
        help='Label to differentiate readers',
        default='Reader',
        track_visibility='onchange',
    )

    number = fields.Integer(
        string='Number',
        help='Number of the reader on the controller',
        index=True,
    )

    # TODO Rename to just 'type'
    reader_type = fields.Selection(
        selection=reader_types,
        string='Reader type',
        help='Type of the reader',
    )

    mode = fields.Selection(
        selection=reader_modes,
        string='Reader mode',
        help='Mode of the reader',
        default='01',
    )

    controller_id = fields.Many2one(
        'hr.rfid.ctrl',
        string='Controller',
        help='Controller that manages the reader',
        required=True,
        ondelete='cascade',
    )

    user_event_ids = fields.One2many(
        'hr.rfid.event.user',
        'reader_id',
        string='Events',
        help='Events concerning this reader',
    )

    door_id = fields.Many2one(
        'hr.rfid.door',
        string='Door',
        help='Door the reader opens',
        ondelete='cascade',
    )

    @api.multi
    def _compute_reader_name(self):
        for record in self:
            record.name = record.door_id.name + ' ' + \
                          self.reader_types[int(record.reader_type)][1] + \
                          ' Reader'

    @api.multi
    def write(self, vals):
        if 'mode' not in vals or ('no_d6_cmd' in vals and vals['no_d6_cmd'] is True):
            super(HrRfidReader, self).write(vals)
            return

        for reader in self:
            old_mode = reader.mode
            super(HrRfidReader, reader).write(vals)
            new_mode = reader.mode

            if old_mode != new_mode:
                ctrl = reader.controller_id
                cmd_env = self.env['hr.rfid.command'].sudo()

                data = ''
                for r in ctrl.reader_ids:
                    data = data + str(r.mode) + '0100'

                cmd_env.create({
                    'webstack_id': ctrl.webstack_id.id,
                    'controller_id': ctrl.id,
                    'cmd': 'D6',
                    'cmd_data': data,
                })


class HrRfidUserEvent(models.Model):
    _name = 'hr.rfid.event.user'
    _description = "RFID User Event"
    _order = 'id desc'

    name = fields.Char(
        compute='_compute_user_ev_name'
    )

    ctrl_addr = fields.Integer(
        string='Controller ID',
        required=True,
        help='ID the controller differentiates itself from the others with on the same webstack'
    )

    workcode = fields.Char(
        string='Workcode (Raw)',
        help="Workcode that arrived from the event. If you are seeing this version, it means that you haven't created "
             'a workcode label for this one in the workcodes page.',
        default='-',
        readonly=True,
    )

    workcode_id = fields.Many2one(
        comodel_name='hr.rfid.workcode',
        string='Workcode',
        help='Workcode that arrived from the event',
        readonly=True,
    )

    employee_id = fields.Many2one(
        'hr.employee',
        string='Employee',
        help='Employee affected by this event',
        ondelete='cascade',
    )

    contact_id = fields.Many2one(
        'res.partner',
        string='Contact',
        help='Contact affected by this event',
        ondelete='cascade',
    )

    door_id = fields.Many2one(
        'hr.rfid.door',
        string='Door',
        help='Door affected by this event',
        ondelete='cascade',
    )

    reader_id = fields.Many2one(
        'hr.rfid.reader',
        string='Reader',
        help='Reader affected by this event',
        required=True,
        ondelete='cascade',
    )

    card_id = fields.Many2one(
        'hr.rfid.card',
        string='Card',
        help='Card affected by this event',
        ondelete='cascade',
    )

    command_id = fields.Many2one(
        'hr.rfid.command',
        string='Response',
        help='Response command',
        readonly=True,
        ondelete='set null',
    )

    event_time = fields.Datetime(
        string='Timestamp',
        help='Time the event triggered',
        required=True,
        index=True,
    )

    action_selection = [
        ('1', 'Granted'),
        ('2', 'Denied'),
        ('3', 'Denied T/S'),
        ('4', 'Denied APB'),
        ('5', 'Exit Button'),
        ('6', 'Granted (no entry)'),
        ('64', 'Request Instructions'),
    ]

    event_action = fields.Selection(
        selection=action_selection,
        string='Action',
        help='What happened to trigger the event',
        required=True,
    )

    action_string = fields.Char(
        compute='_compute_user_ev_action_str',
    )

    @api.model
    def _delete_old_events(self):
        event_lifetime = self.env['ir.config_parameter'].get_param('hr_rfid.event_lifetime')
        if event_lifetime is None:
            return False

        lifetime = timedelta(days=int(event_lifetime))
        today = datetime.today()
        res = self.search([
            ('event_time', '<', today-lifetime)
        ])
        res.unlink()

        return self.env['hr.rfid.event.system'].delete_old_events()

    @api.multi
    def _compute_user_ev_name(self):
        for record in self:
            if record.employee_id:
                name = record.employee_id.name
            elif record.contact_id:
                name = record.contact_id.name
            else:
                name = record.door_id.name
            name += ' - '
            if record.event_action != '64':
                name += self.action_selection[int(record.event_action)-1][1]
            else:
                name += 'Request Instructions'
            if record.door_id:
                name += ' @ ' + record.door_id.name
            record.name = name

    @api.multi
    def _compute_user_ev_action_str(self):
        for record in self:
            record.action_string = 'Access ' + self.action_selection[int(record.event_action)-1][1]


class HrRfidSystemEvent(models.Model):
    _name = 'hr.rfid.event.system'
    _description = 'RFID System Event'
    _order = 'id desc'

    name = fields.Char(
        compute='_compute_sys_ev_name'
    )

    webstack_id = fields.Many2one(
        'hr.rfid.webstack',
        string='Module',
        help='Module affected by this event',
        default=None,
        ondelete='cascade',
    )

    controller_id = fields.Many2one(
        'hr.rfid.ctrl',
        string='Controller',
        help='Controller affected by this event',
        default=None,
        ondelete='cascade',
    )

    timestamp = fields.Datetime(
        string='Timestamp',
        help='Time the event occurred',
        required=True,
        index=True,
    )

    action_selection = [
        ('1', 'DuressOK'),
        ('2', 'DuressError'),
        ('3', 'R1 Card OK'),
        ('4', 'R1 Card Error'),
        ('5', 'R1 T/S Error'),
        ('6', 'R1 APB Error'),
        ('7', 'R2 Card OK'),
        ('8', 'R2 Card Error'),
        ('9', 'R2 T/S Error'),
        ('10', 'R2 APB Error'),
        ('11', 'R3 Card OK'),
        ('12', 'R3 Card Error'),
        ('13', 'R3 T/S Error'),
        ('14', 'R3 APB Error'),
        ('15', 'R4 Card Ok'),
        ('16', 'R4 Card Error'),
        ('17', 'R4 T/S Error'),
        ('18', 'R4 APB Error'),
        ('19', 'EmergencyOpenDoor'),
        ('20', 'ON/OFF Siren'),
        ('21', 'OpenDoor1 from In1'),
        ('22', 'OpenDoor2 from In2'),
        ('23', 'OpenDoor3 from In3'),
        ('24', 'OpenDoor4 from In4'),
        ('25', 'Dx Overtime'),
        ('26', 'ForcedOpenDx'),
        ('27', 'DELAY ZONE ON (if out) Z4,Z3,Z2,Z1'),
        ('28', 'DELAY ZONE OFF (if in) Z4,Z3,Z2,Z1'),
        ('29', ''),
        ('30', 'Power On event'),
        ('31', 'Open/Close Door From PC'),
        ('45', '1-W ERROR (wiring problems)'),
        ('47', 'Vending Purchase Complete'),
        ('48', 'Vending Error1'),
        ('49', 'Vending Error2'),
        ('64', 'Vending Request User Balance'),
    ]

    event_action = fields.Selection(
        selection=action_selection,
        string='Event Type',
    )

    error_description = fields.Char(
        string='Description',
        help='Description on why the error happened',
    )

    input_js = fields.Char(
        string='Input JSON',
    )

    @api.model
    def delete_old_events(self):
        event_lifetime = self.env['ir.config_parameter'].get_param('hr_rfid.event_lifetime')
        if event_lifetime is None:
            return False

        lifetime = timedelta(days=int(event_lifetime))
        today = datetime.today()
        res = self.search([
            ('timestamp', '<', today-lifetime)
        ])
        res.unlink()

        return True

    @api.multi
    def _compute_sys_ev_name(self):
        for record in self:
            record.name = str(record.webstack_id.name) + '-' + str(record.controller_id.name) +\
                          ' at ' + str(record.timestamp)

    def _check_save_comms(self, vals):
        save_comms = self.env['ir.config_parameter'].get_param('hr_rfid.save_webstack_communications')
        if save_comms != 'True':
            if 'input_js' in vals:
                vals.pop('input_js')

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            self._check_save_comms(vals)
        return super(HrRfidSystemEvent, self).create(vals_list)

    @api.multi
    def write(self, vals):
        self._check_save_comms(vals)
        return super(HrRfidSystemEvent, self).write(vals)


class HrRfidSystemEventWizard(models.TransientModel):
    _name = 'hr.rfid.event.sys.wiz'
    _description = 'Add card to employee/contact'

    def _default_sys_ev(self):
        return self.env['hr.rfid.event.system'].browse(self._context.get('active_ids'))

    def _default_card_number(self):
        sys_ev = self._default_sys_ev()
        js = json.loads(sys_ev.input_js)
        try:
            card_number = js['event']['card']
            return card_number
        except KeyError as _:
            raise exceptions.ValidationError('System event does not have a card number in it')

    sys_ev_id = fields.Many2one(
        'hr.rfid.event.system',
        string='System event',
        required=True,
        default=_default_sys_ev,
        ondelete='cascade',
    )

    employee_id = fields.Many2one(
        'hr.employee',
        string='Card owner (employee)',
    )

    contact_id = fields.Many2one(
        'res.partner',
        stirng='Card owner (contact)',
    )

    card_number = fields.Char(
        string='Card Number',
        default=_default_card_number,
    )

    card_type = fields.Many2one(
        'hr.rfid.card.type',
        string='Card type',
        help='Only doors that support this type will be able to open this card',
        default=lambda self: self.env.ref('hr_rfid.hr_rfid_card_type_def').id,
    )

    activate_on = fields.Datetime(
        string='Activate on',
        help='Date and time the card will be activated on',
        track_visibility='onchange',
        default=lambda self: datetime.now(),
    )

    deactivate_on = fields.Datetime(
        string='Deactivate on',
        help='Date and time the card will be deactivated on',
        track_visibility='onchange',
    )

    card_active = fields.Boolean(
        string='Active',
        help='Whether the card is active or not',
        track_visibility='onchange',
        default=True,
    )

    cloud_card = fields.Boolean(
        string='Cloud Card',
        help='A cloud card will not be added to controllers that are in the "externalDB" mode.',
        default=True,
        required=True,
    )

    @api.multi
    def add_card(self):
        self.ensure_one()

        if len(self.contact_id) == len(self.employee_id):
            raise exceptions.ValidationError(
                'Card cannot have both or neither a contact owner and an employee owner.'
            )

        card_env = self.env['hr.rfid.card']
        new_card = {
            'number': self.card_number,
            'card_type': self.card_type.id,
            'activate_on': self.activate_on,
            'deactivate_on': self.deactivate_on,
            'card_active': self.card_active,
            'cloud_card': self.cloud_card,
        }
        if len(self.contact_id) > 0:
            new_card['contact_id'] = self.contact_id.id
        else:
            new_card['employee_id'] = self.employee_id.id
        card_env.create(new_card)


class HrRfidCommands(models.Model):
    # Commands we have queued up to send to the controllers
    _name = 'hr.rfid.command'
    _description = 'Command to controller'
    _order = 'id desc'

    commands = [
        ('F0', 'Read System Information'),
        ('F1', 'Read/Search Card And Info'),
        ('F2', 'Read Group of Cards'),
        ('F3', 'Read Time Schedules'),
        ('F4', 'Read Holiday List'),
        ('F5', 'Read Controller Mode'),
        ('F6', 'Read Readers Mode'),
        ('F7', 'Read System Clock'),
        ('F8', 'Read Duress Mode'),
        ('F9', 'Read Input/Output Table'),
        ('FB', 'Read Inputs Flags'),
        ('FC', 'Read Anti-Passback Mode'),
        ('FD', 'Read Fire & Security Status'),
        ('FE', 'Read FireTime, Sound_Time'),
        ('FF', 'Read Output T/S Table'),
        ('D0', 'Write Controller ID'),
        ('D1', 'Add/Delete Card'),
        ('D2', 'Delete Card'),
        ('D3', 'Write Time Schedules'),
        ('D4', 'Write Holiday List'),
        ('D5', 'Write Controller Mode'),
        ('D6', 'Write Readers Mode'),
        ('D7', 'Write Controller System Clock'),
        ('D8', 'Write Duress Mode'),
        ('D9', 'Write Input/Output Table'),
        ('DA', 'Delete Last Event'),
        ('DB', 'Open Output'),
        ('DB2', 'Sending Balance To Vending Machine'),
        ('DC', 'System Initialization'),
        ('DD', 'Write Input Flags'),
        ('DE', 'Write Anti-Passback Mode'),
        ('DF', 'Write Outputs T/S Table'),
        ('D3', 'Delete Time Schedule'),
        ('B3', 'Read Controller Status'),
    ]

    statuses = [
        ('Wait', 'Command Waiting for Webstack Communication'),
        ('Process', 'Command Processing'),
        ('Success', 'Command Execution Successful'),
        ('Failure', 'Command Execution Unsuccessful'),
    ]

    errors = [
        ('0', 'No Error'),
        ('1', 'I2C Error'),
        ('2', 'I2C Error'),
        ('3', 'RS485 Error'),
        ('4', 'Wrong Value/Parameter'),
        ('5', 'CRC Error'),
        ('6', 'Memory Error'),
        ('7', 'Cards Overflow'),
        ('8', 'Not Use'),
        ('9', 'Card Not Found'),
        ('10', 'No Cards'),
        ('11', 'Not Use'),
        ('12', 'Controller Busy, Local Menu Active or Master Card Mode in Use'),
        ('13', '1-Wire Error'),
        ('14', 'Unknown Command'),
        ('20', 'No Response from controller (WebSDK)'),
        ('21', 'Bad JSON Structure (WebSDK)'),
        ('22', 'Bad CRC from Controller (WebSDK)'),
        ('23', 'Bridge is Currently in Use (WebSDK)'),
        ('24', 'Internal Error, Try Again (WebSDK)'),
        ('30', 'No response from the Module'),
        ('31', 'Incorrect Data Response'),
    ]

    name = fields.Char(
        compute='_compute_cmd_name',
    )

    webstack_id = fields.Many2one(
        'hr.rfid.webstack',
        string='Module',
        help='Module the command is/was intended for',
        required=True,
        readonly=True,
        ondelete='cascade',
    )

    controller_id = fields.Many2one(
        'hr.rfid.ctrl',
        string='Controller',
        help='Controller the command is/was intended for',
        required=True,
        readonly=True,
        ondelete='cascade',
        index=True,
    )

    cmd = fields.Selection(
        selection=commands,
        string='Command',
        help='Command to send/have sent to the module',
        required=True,
        readonly=True,
        index=True,
    )

    cmd_data = fields.Char(
        string='Command data',
        help='Additional data sent to the controller',
        default='',
        readonly=True,
    )

    status = fields.Selection(
        selection=statuses,
        string='Status',
        help='Current status of the command',
        default='Wait',
        index=True,
    )

    error = fields.Selection(
        selection=errors,
        string='Error',
        help='If status is "Command Unsuccessful" this field is updated '
             'to the reason for why it was unsuccessful',
        default='0'
    )

    cr_timestamp = fields.Datetime(
        string='Creation Time',
        help='Time at which the command was created',
        readonly=True,
        required=True,
        default=lambda self: datetime.now(),
    )

    ex_timestamp = fields.Datetime(
        string='Execution Time',
        help='Time at which the module returned a response from the command',
    )

    request = fields.Char(
        string='Request',
        help='Request json sent to the module'
    )

    response = fields.Char(
        string='Response',
        help='Response json sent from the module',
    )

    card_number = fields.Char(
        string='Card',
        help='Card the command will do an operation for',
        limit=10,
        index=True,
    )

    retries = fields.Integer(
        string='Command retries',
        help='How many times the command failed to run and has been retried',
        default=0,
    )

    pin_code = fields.Char(string='Pin Code (debug info)')
    ts_code = fields.Char(string='TS Code (debug info)', limit=8)
    rights_data = fields.Integer(string='Rights Data (debug info)')
    rights_mask = fields.Integer(string='Rights Mask (debug info)')

    @api.multi
    def _compute_cmd_name(self):
        def find_desc(cmd):
            for it in HrRfidCommands.commands:
                if it[0] == cmd:
                    return it[1]

        for record in self:
            record.name = str(record.cmd) + ' ' + find_desc(record.cmd)

    @api.model
    def create_d1_cmd(self, ws_id, ctrl_id, card_num, pin_code, ts_code, rights_data, rights_mask):
        self.create([{
            'webstack_id': ws_id,
            'controller_id': ctrl_id,
            'cmd': 'D1',
            'card_number': card_num,
            'pin_code': pin_code,
            'ts_code': ts_code,
            'rights_data': rights_data,
            'rights_mask': rights_mask,
        }])

    @api.model
    def add_remove_card(self, card_number, ctrl_id, pin_code, ts_code, rights_mask, rights_data):
        ctrl = self.env['hr.rfid.ctrl'].browse(ctrl_id)
        commands_env = self.env['hr.rfid.command']

        old_cmd = commands_env.search([
            ('cmd', '=', 'D1'),
            ('status', '=', 'Wait'),
            ('card_number', '=', card_number),
            ('controller_id', '=', ctrl.id),
        ])

        if len(old_cmd) == 0:
            commands_env.create_d1_cmd(ctrl.webstack_id.id, ctrl.id,
                                       card_number, pin_code, ts_code, rights_data, rights_mask)
        else:
            new_ts_code = ''
            if str(ts_code) != '':
                for i in range(4):
                    num_old = int(old_cmd.ts_code[i*2:i*2+2], 16)
                    num_new = int(ts_code[i*2:i*2+2], 16)
                    if num_new == 0:
                        num_new = num_old
                    new_ts_code += '%02X' % num_new
            else:
                new_ts_code = old_cmd.ts_code
            write_dict = {
                'pin_code': pin_code,
                'ts_code': new_ts_code,
            }

            new_rights_data = 0
            new_rights_mask = 0
            for i in range(8):
                bit = 1 << i
                if rights_mask & bit == 0 and old_cmd.rights_mask & bit > 0:
                    new_rights_mask |= old_cmd.rights_mask & bit
                    new_rights_data |= old_cmd.rights_data & bit
                else:
                    new_rights_mask |= rights_data & bit
                    new_rights_data |= rights_mask & bit

            write_dict['rights_mask'] = new_rights_mask
            write_dict['rights_data'] = new_rights_data

            old_cmd.write(write_dict)

    @api.model
    def add_card(self, door_id, ts_id, pin_code, card_id):
        door = self.env['hr.rfid.door'].browse(door_id)
        time_schedule = self.env['hr.rfid.time.schedule'].browse(ts_id)
        card = self.env['hr.rfid.card'].browse(card_id)
        card_number = card.number

        for reader in door.reader_ids:
            ts_code = [0, 0, 0, 0]
            ts_code[reader.number-1] = time_schedule.number
            ts_code = '%02X%02X%02X%02X' % (ts_code[0], ts_code[1], ts_code[2], ts_code[3])
            self.add_remove_card(card_number, door.controller_id.id, pin_code, ts_code,
                                 1 << (reader.number-1), 1 << (reader.number-1))

    @api.model
    def remove_card(self, door_id, pin_code, card_number=None, card_id=None):
        door = self.env['hr.rfid.door'].browse(door_id)

        if card_id is not None:
            card = self.env['hr.rfid.card'].browse(card_id)
            card_number = card.number

        for reader in door.reader_ids:
            self.add_remove_card(card_number, door.controller_id.id, pin_code, '00000000',
                                 1 << (reader.number-1), 0)

    @api.model
    def _update_commands(self):
        failed_commands = self.search([
            ('status', '=', 'Process'),
            ('cr_timestamp', '<', str(fields.datetime.now() - timedelta(minutes=1)))
        ])

        for it in failed_commands:
            it.write({
                'status': 'Failure',
                'error': '30',
            })

        failed_commands = self.search([
            ('status', '=', 'Wait'),
            ('cr_timestamp', '<', str(fields.datetime.now() - timedelta(minutes=1)))
        ])

        for it in failed_commands:
            it.write({
                'status': 'Failure',
                'error': '30',
            })

    @api.model
    def _sync_clocks(self):
        ws_env = self.env['hr.rfid.webstack']
        commands_env = self.env['hr.rfid.command']

        controllers = ws_env.search([('ws_active', '=', True)]).mapped('controllers')

        for ctrl in controllers:
            commands_env.create([{
                'webstack_id': ctrl.webstack_id.id,
                'controller_id': ctrl.id,
                'cmd': 'D7',
            }])

    def _check_save_comms(self, vals):
        save_comms = self.env['ir.config_parameter'].get_param('hr_rfid.save_webstack_communications')
        if save_comms != 'True':
            if 'request' in vals:
                vals.pop('request')
            if 'response' in vals:
                vals.pop('response')

    @api.model_create_multi
    def create(self, vals_list: list):
        def find_last_wait(_cmd, _vals):
            ret = self.search([
                ('webstack_id', '=', _vals['webstack_id']),
                ('controller_id', '=', _vals['controller_id']),
                ('cmd', '=', _cmd),
                ('status', '=', 'Wait'),
            ])
            if len(ret) > 0:
                return ret[-1]
            return ret

        records = self.env['hr.rfid.command']
        for vals in vals_list:
            self._check_save_comms(vals)

            cmd = vals['cmd']
            res = find_last_wait(cmd, vals)

            if len(res) == 0:
                records += super(HrRfidCommands, self).create([vals])
                continue

            cmd_data = vals.get('cmd_data', False)

            if cmd == 'DB':
                if res.cmd_data[0] == cmd_data[0] and res.cmd_data[1] == cmd_data[1]:
                    res.cmd_data = cmd_data
                    continue
            elif cmd == 'D9' or cmd == 'D5':
                res.cmd_data = cmd_data
                continue
            elif cmd == 'D7':
                continue

            records += super(HrRfidCommands, self).create([vals])

        return records

    @api.multi
    def write(self, vals):
        self._check_save_comms(vals)
        return super(HrRfidCommands, self).write(vals)
