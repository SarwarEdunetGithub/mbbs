from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver

from .models import StudentProfile


@receiver(post_delete, sender=StudentProfile)
def delete_student_photo_on_delete(sender, instance: StudentProfile, **kwargs):
    """
    Delete the underlying photo file when a StudentProfile row is deleted.
    Covers cascade deletes when a User is deleted.
    """
    if instance.photo:
        try:
            instance.photo.delete(save=False)
        except Exception:
            pass


@receiver(pre_save, sender=StudentProfile)
def delete_student_photo_on_change(sender, instance: StudentProfile, **kwargs):
    """
    If the profile photo is changed, remove the old file from storage.
    """
    if not instance.pk:
        return
    try:
        old = StudentProfile.objects.get(pk=instance.pk)
    except StudentProfile.DoesNotExist:
        return
    if old.photo and old.photo.name and old.photo.name != getattr(instance.photo, 'name', None):
        try:
            old.photo.delete(save=False)
        except Exception:
            pass

