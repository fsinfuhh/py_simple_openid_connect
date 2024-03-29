# Generated by Django 4.2.5 on 2023-11-13 08:58

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("simple_openid_connect_django", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="openiduser",
            name="_id_token",
        ),
        migrations.AddField(
            model_name="openidsession",
            name="_id_token",
            field=models.TextField(
                default="{}",
                verbose_name="json representation of this sessions is token",
            ),
            preserve_default=False,
        ),
    ]
