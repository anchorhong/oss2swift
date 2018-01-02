import oss2swift


extensions = ['sphinx.ext.autodoc', 'sphinx.ext.doctest', 'sphinx.ext.todo',
              'sphinx.ext.coverage']


templates_path = ['_templates']

source_suffix = '.rst'


master_doc = 'index'

project = u'Swift Oss2Swift Compatibility Middleware'
copyright = u''


version = '.'.join(str(v) for v in oss2swift.version_info[:-1])

release = oss2swift.version


exclude_trees = []


pygments_style = 'sphinx'


html_theme = 'default'


html_static_path = ['_static']


htmlhelp_basename = ''
