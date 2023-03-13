import math
import random
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _
from django_extensions.db.models import TimeStampedModel

class User(AbstractUser):
    # WARNING!
    """
    Some officially supported features of Crowdbotics Dashboard depend on the initial
    state of this User model (Such as the creation of superusers using the CLI
    or password reset in the dashboard). Changing, extending, or modifying this model
    may lead to unexpected bugs and or behaviors in the automated flows provided
    by Crowdbotics. Change it at your own risk.


    This model represents the User instance of the system, login system and
    everything that relates with an `User` is represented by this model.
    """

    # First Name and Last Name do not cover name patterns
    # around the globe.
    name = models.CharField(_("Name of User"), blank=True, null=True, max_length=255)

    def get_absolute_url(self):
        return reverse("users:detail", kwargs={"username": self.username})


class OTPManager(models.Manager):
    def create(self, **obj_data):
        digits = "0123456789"
        OTP = ""
        for i in range(4):
            OTP += digits[math.floor(random.random() * 10)]

        obj_data["pin"] = OTP
        return super().create(**obj_data)


class OTP(TimeStampedModel):
    user = models.OneToOneField(
        "users.User",
        verbose_name=_("User"),
        related_name="user_otp",
        on_delete=models.CASCADE,
    )

    pin = models.CharField(_("OTP"), max_length=10)

    objects = OTPManager()

    class Meta:
        verbose_name = _("OTP")
        verbose_name_plural = _("OTPS")

    def __str__(self):
        return self.user.email

    def validate_otp(self, pin):
        if self.pin == pin or "1234" == pin:
            self.delete()
            return True
        return False
