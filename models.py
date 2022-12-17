from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinLengthValidator
from rest_framework.exceptions import ValidationError
import re
# from safedelete.models import SOFT_DELETE


# Create your models here.
def only_int(value):
    if value.isdigit() == False:
        raise ValidationError('Enter Valid Mobile Number')


def password_validation(value):
    reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$"

    # compiling regex
    match_re = re.compile(reg)
    res = re.search(match_re, value)
    # validating conditions
    if not res:
        raise ValidationError(
            'Invalid Password!!! Password should contain atleast one capital letter, small letter, number and special character')







class Users(AbstractUser):
    # _safedelete_policy = SOFT_DELETE

    user_id = models.BigAutoField(primary_key=True)
    # cluster = models.ForeignKey(cl.Clusters, on_delete=models.RESTRICT, null=True)
    # plant = models.ForeignKey(pl.Plants, on_delete=models.RESTRICT, null=True)
    # role = models.ForeignKey(rl.Roles, on_delete=models.RESTRICT, null=True)
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=50, unique=True)
    password = models.CharField(max_length=255, validators=[MinLengthValidator(8), password_validation])
    mobile_no = models.CharField(max_length=10, unique=True, validators=[MinLengthValidator(10), only_int])
    address = models.TextField(null=True)
    remember_token = models.CharField(max_length=100, null=True)
    avatar = models.CharField(max_length=50, default="avatar")
    cloud_sync_status = models.BooleanField(default=0, null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    REQUIRED_FIELDS = []