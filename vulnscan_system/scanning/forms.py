from django import forms
from .engine import parse_targets
from .models import Target, ScanJob


class TargetForm(forms.ModelForm):
    def clean_ip_or_cidr(self):
        value = self.cleaned_data["ip_or_cidr"].strip()
        parsed = parse_targets(value)
        if any(isinstance(target, str) for target in parsed):
            raise forms.ValidationError("Enter an IP address or CIDR network for a network scan.")
        if len(parsed) != 1:
            raise forms.ValidationError("Enter one IP address or CIDR network per target.")
        return value

    class Meta:
        model = Target
        fields = ("label", "ip_or_cidr")
        widgets = {
            "ip_or_cidr": forms.TextInput(attrs={"placeholder": "e.g. 10.0.0.0/24 or 10.0.0.15"}),
        }


class ScanJobForm(forms.ModelForm):
    class Meta:
        model = ScanJob
        fields = ("scan_type", "nmap_arguments")
        widgets = {
            "nmap_arguments": forms.TextInput(attrs={"placeholder": "-sV -O --top-ports 100"}),
        }
