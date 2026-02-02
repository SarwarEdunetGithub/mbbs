from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver

from .models import Document


@receiver(post_delete, sender=Document)
def delete_document_file_on_delete(sender, instance: Document, **kwargs):
    """
    Delete the underlying file when a Document row is deleted.
    This also covers cascade deletes (e.g., when a student user is deleted).
    """
    if instance.file:
        try:
            instance.file.delete(save=False)
        except Exception:
            # Don't break the request if storage cleanup fails.
            pass


@receiver(pre_save, sender=Document)
def delete_document_file_on_change(sender, instance: Document, **kwargs):
    """
    If a Document is updated with a new file, remove the old file from storage.
    """
    if not instance.pk:
        return
    try:
        old = Document.objects.get(pk=instance.pk)
    except Document.DoesNotExist:
        return
    if old.file and old.file.name and old.file.name != getattr(instance.file, 'name', None):
        try:
            old.file.delete(save=False)
        except Exception:
            pass

