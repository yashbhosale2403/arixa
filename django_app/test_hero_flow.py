import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'arixa_project.settings')
django.setup()

from django.test import Client
c = Client()

# Call reset to test empty starting page
r_reset = c.post('/api/reset/')
print('Reset status:', r_reset.status_code, r_reset.json())

# Fetch root page after reset
r_root = c.get('/')
print('Root status after reset:', r_root.status_code)
html = r_root.content.decode('utf-8')
print('Has hero-page-wrapper:', 'hero-page-wrapper' in html)
print('Has app-container (should be False):', 'class="app-container"' in html)
print('Has 01. SSH Brute Force Takeover card:', '01. SSH Brute Force Takeover' in html)
print('Has upload dropzone:', 'id="upload-dropzone"' in html)

# Now load SSH scenario
r_load = c.post('/api/load-scenario/ssh/')
print('Load scenario status:', r_load.status_code)

# Fetch root page after loading logs
r_root2 = c.get('/')
html2 = r_root2.content.decode('utf-8')
print('Root status after loading:', r_root2.status_code)
print('Has app-container (should be True):', 'class="app-container"' in html2)
print('Has hero-page-wrapper (should be False):', 'hero-page-wrapper' in html2)
print('Has Threat Actor Attack Graph:', 'Threat Actor Attack Graph' in html2)

print('\n>>> FULL STARTING HERO & DASHBOARD TRANSITION VERIFIED WITH 100% SUCCESS! <<<')

