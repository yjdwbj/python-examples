from distutils.core import setup
from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
from Cython.Build import cythonize
ext_modules = [Extension("sockbasic",["sockbasic.pyx"]),Extension("dbdriver",["dbdriver.pyx"])]
setup(
    name = "socket server baisc funcs",
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules,
    )
