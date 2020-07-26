from django import forms
from django.core.signing import Signer

"""
A secure implementation of the Django Form class.
Validates a hash of proected (hidden) values against a signature created 
with Django's own cryptographic signing system.

Make sure the form_hash field is added to your templates if you are 
creating forms manually.

Usage:

In forms.py:
class MyForm(SecureForm):
    name = forms.CharField(required=True, widget=forms.TextInput())
    user_id = forms.IntegerField(required=True, widget=forms.HiddenInput())
    ...
    
In views.py:
form = MyForm(initial={'user_id': request.user.id})
...then where you get POST data...
form = MyForm(request.POST)
if form.is_valid():
    # do something...
...and process the form as normal...
    
In template.html:
{{ form }}
...or to get the hash value manually: {{ form.form_hash }}
"""
class SecureForm(forms.Form):

    def __init__(self, *args, **kwargs):
        exclude_fields = kwargs.pop("exclude_fields", None)
        super(SecureForm, self).__init__(*args, **kwargs)
        form_hash = forms.CharField(widget=forms.HiddenInput(), required=False)
        self.fields.update({'form_hash': form_hash})
        self.exclude_fields = ["form_hash"]
        if exclude_fields and isinstance(exclude_fields, (list, tuple)):
            self.exclude_fields += list(exclude_fields)
        hash_str = u""
        for name, field in self.fields.items():
            if field.widget.is_hidden and name not in self.exclude_fields and (self.initial.get(name, None) or field.initial):
                hash_str += str(self.initial.get(name, None)) or str(field.initial)
        if hash_str:
            signer = Signer()
            hash_val = signer.sign(hash_str).split(":")[1]
            self.initial['form_hash'] = hash_val

    def clean(self):
        cleaned_data = super(SecureForm, self).clean()
        hash_str = u""
        for name, field in self.fields.items():
            if field.widget.is_hidden and name not in self.exclude_fields and cleaned_data.get(name, None):
                hash_str += str(str(cleaned_data[name]))
        if hash_str:
            signer = Signer()
            hash_val = signer.sign(hash_str).split(":")[1]
            form_hash = cleaned_data['form_hash']
            if hash_val and hash_val != form_hash:
                raise forms.ValidationError("Tampering has been detected in the form. Please try again.")
        return cleaned_data
