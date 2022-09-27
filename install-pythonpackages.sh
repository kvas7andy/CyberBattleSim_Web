#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

. ./getpythonpath.sh

# Install python packages
$PYTHON -m pip install --upgrade pip
$PYTHON -m pip install wheel
$PYTHON -m pip install -e .
$PYTHON -m pip install -e .[dev]
$PYTHON -m pip install jupyter_contrib_nbextensions && jupyter contrib nbextension install 

if [ ""$GITHUB_ACTION"" == "" ]; then
  # Only install the `pre-commit` package
  # if running on a dev box and not under GitHub Actions
  $PYTHON -m pip install pre-commit
fi
