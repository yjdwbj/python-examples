# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('radio', '0003_auto_20150707_0646'),
    ]

    operations = [
        migrations.CreateModel(
            name='PhoneUser',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('pmodel', models.CharField(max_length=50)),
                ('pimei', models.CharField(max_length=15)),
                ('paddr', models.GenericIPAddressField()),
            ],
        ),
    ]
