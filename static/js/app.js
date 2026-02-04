/**
 * Accounts – password toggling & lightweight form validation
 * No extra frameworks; vanilla JS.
 */
(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState !== 'loading') fn();
    else document.addEventListener('DOMContentLoaded', fn);
  }

  // ----- Password visibility toggle -----
  function initPasswordToggles() {
    document.querySelectorAll('.password-toggle-wrapper').forEach(function (wrapper) {
      var input = wrapper.querySelector('input');
      var btn = wrapper.querySelector('[data-password-toggle]');
      if (!input || !btn) return;

      btn.setAttribute('aria-label', input.type === 'password' ? 'Show password' : 'Hide password');

      btn.addEventListener('click', function () {
        var isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
        var icon = btn.querySelector('i');
        if (icon) {
          icon.classList.toggle('bi-eye', !isPassword);
          icon.classList.toggle('bi-eye-slash', isPassword);
        }
      });
    });
  }

  // ----- Inline validation (optional, enhance server errors) -----
  function initFormValidation() {
    document.querySelectorAll('form[data-validate]').forEach(function (form) {
      form.addEventListener('submit', function (e) {
        var valid = true;
        form.querySelectorAll('[required]').forEach(function (field) {
          var group = field.closest('.mb-3');
          if (!group) return;
          if (!field.value || !field.value.trim()) {
            group.classList.add('was-validated');
            valid = false;
          } else {
            group.classList.remove('was-validated');
          }
        });
        if (!valid) e.preventDefault();
      });

      form.querySelectorAll('[required]').forEach(function (field) {
        field.addEventListener('blur', function () {
          var group = field.closest('.mb-3');
          if (!group) return;
          if (field.value.trim()) group.classList.remove('was-validated');
          else group.classList.add('was-validated');
        });
      });
    });
  }

  ready(function () {
    initPasswordToggles();
    initFormValidation();
  });
})();
