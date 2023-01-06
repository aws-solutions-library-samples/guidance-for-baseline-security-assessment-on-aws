#!/bin/sh

sed 's/^/\           /' ../source/custom_lens_import_lambda.py > custom_lens_import_lambda.deployment
sed '/ZipFile/ r custom_lens_import_lambda.deployment' ../source/security_essentials_source.template > security_essentials_deployment.template
rm custom_lens_import_lambda.deployment