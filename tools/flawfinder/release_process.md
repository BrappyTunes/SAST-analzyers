# Release process

Here's information on how to release an update to flawfinder.

## Set up a virtual environment

It is recommended to work inside a virtual environment to ensure
dependencies such as `setuptools` and `twine` are available:

~~~~
python3 -m venv venv
source venv/bin/activate   # re-run this in each new shell session
pip install setuptools twine wheel
~~~~

## Changing version number

Ensure that the version number is the intended final value.
Make sure every different release has a unique version number,
and that the number is consistent across all our files for
a given release.

To change version number, edit the following files:
makefile
flawfinder.py
flawfinder.spec
setup.py
index.html # in dwheeler.com/flawfinder

Run `make check` until the output stabilises, then accept the new
expected results:

~~~~
make check
make test-is-correct
~~~~

## Test it

Run the test suite with the default Python 3 interpreter:

~~~~
make check
~~~~

To test with a specific Python version, set the `PYTHON` variable:

~~~~
make PYTHON=python3.11 check
~~~~

Python 2 testing is no longer required (installing Python 2 is
increasingly difficult), but can be done the same way if available:

~~~~
make PYTHON=python2 check
~~~~

## Commit it

~~~~
git commit -asv
~~~~

## Tag version

Once you're sure this is the *real* version, tag it:

~~~~
git tag VERSION
git push --tags sourceforge # SourceForge
git push --tags origin # (or "github") GitHub
~~~~

## Create tarball

Run:

~~~~
make distribute
~~~~


## Post tarball

Then post the tarball flawfinder-VERSION.tar.gz to
the usual places:

* SourceForge "files" directory, and set it to be the default download.
* dwheeler.com/flawfinder

Do this *before* creating the PyPi distribution package for pip.

## Post to pip

First, ensure the packaging tools are installed (see venv setup above).

On Windows (Cygwin), pip may not be available yet and
must be bootstrapped first:

~~~~
python -m ensurepip
pip install --upgrade pip
~~~~

Then create a PyPi distribution package:

~~~~
make pypi
~~~~

Now upload the PyPi distribution package:

~~~~
make upload-pypi
~~~~

## After it's uploaded

Change the version number in the repo NOW, so that there will not
be two different released versions with the same version number.
See the list at the beginning of this document for the list of
files to change.
