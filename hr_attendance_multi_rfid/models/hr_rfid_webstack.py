# -*- coding: utf-8 -*-
from openerp import models, api, fields, exceptions


class HrRfidDoor(models.Model):
    _inherit = "hr.rfid.door"

    attendance = fields.Boolean(
        string='Attendance',
        help='Door will track attendance if ticked. Door must '
             'have an in and an out reader to track attendance',
        default=False,
    )

    @api.onchange('attendance')
    def _attendance_on_change(self):
        if self.attendance is True:
            has_in = False
            has_out = False
            has_workcode = False
            for reader in self.reader_ids:
                has_workcode = has_workcode or reader.mode   == '03'  # Workcode mode
                has_in       = has_in or reader.reader_type  == '0'
                has_out      = has_out or reader.reader_type == '1'

            if (has_in is False or has_out is False) and has_workcode is False:
                raise exceptions.ValidationError('This door cannot track attendance because it does not'
                                                 ' have both an In and Out reader, or a reader with the'
                                                 ' mode "Card and workcode".')

    @api.multi
    @api.constrains('attendance')
    def _attendance_constrains(self):
        for door in self:
            if door.attendance is True:
                has_in = False
                has_out = False
                has_wc = False
                for reader in door.reader_ids:
                    has_wc  = has_wc  or reader.mode   == '03'  # Workcode mode
                    has_in  = has_in  or reader.reader_type  == '0'
                    has_out = has_out or reader.reader_type == '1'

                if (has_in is False or has_out is False) and has_wc is False:
                    raise exceptions.ValidationError('This door cannot track attendance because it does not'
                                                     ' have both an In and Out reader, or a reader with the'
                                                     ' mode "Card and workcode".')



