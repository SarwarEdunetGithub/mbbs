from django.db import migrations


def forwards(apps, schema_editor):
    StudentProfile = apps.get_model('students', 'StudentProfile')
    StudentProfile.objects.filter(passport_number='').update(passport_number=None)


class Migration(migrations.Migration):

    dependencies = [
        ('students', '0002_studentprofile_photo_alter_studentprofile_address_and_more'),
    ]

    operations = [
        migrations.RunPython(forwards, reverse_code=migrations.RunPython.noop),
    ]
