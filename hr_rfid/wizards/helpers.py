from openerp import fields, models


class DialogBox(models.TransientModel):
    _name = 'hr.rfid.wiz.dialog.box'
    _description = 'Dialog box wizard helper'

    text = fields.Char(string='Text', readonly=True)


def return_wiz_form_view(res_model, res_id, title=''):
    return {
        'name': title,
        'type': 'ir.actions.act_window',
        'res_model': res_model,
        'view_mode': 'form',
        'view_type': 'form',
        'res_id': res_id,
        'views': [(False, 'form')],
        'target': 'new',
    }


def create_dialog_box(env, text):
    return env['hr.rfid.wiz.dialog.box'].create({
        'text': text,
    })


def return_dialog_box(d_box, title=''):
    return return_wiz_form_view('hr.rfid.wiz.dialog.box', d_box.id, title)


def create_and_ret_d_box(env, title, text):
    d_box = create_dialog_box(env, text)
    return return_dialog_box(d_box, title)




