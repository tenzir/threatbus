import os
import site
import sys

home = os.path.join(sys.prefix, "lib", "python")
site.addsitedir(home)
