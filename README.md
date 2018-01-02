oss2swift
-------

Features
-------
 - Support Services APIs (GET)
 - Support Bucket APIs (GET/PUT/DELETE/HEAD)
 - Support Object APIs (GET/PUT/DELETE/HEAD)
 - Support Multipart Upload (required **SLO** middleware support)
 - Support OSS ACL (**support bucket acl**)

Install
-------

1) Install oss2swift with ``sudo python setup.py install`` or ``sudo python
   setup.py develop`` or via whatever packaging system you may be using.

2) Alter your proxy-server.conf pipeline to have oss2swift:

If you use tempauth:

    Was::

        [pipeline:main]
        pipeline = catch_errors cache tempauth proxy-server

    Change To::

        [pipeline:main]
        pipeline = catch_errors cache oss2swift tempauth proxy-server

    To support Multipart Upload::

        [pipeline:main]
        pipeline = catch_errors cache oss2swift tempauth slo proxy-server


If you use swauth:

    Was::

        [pipeline:main]
        pipeline = catch_errors cache tempauth proxy-server

    Change To::

        [pipeline:main]
        pipeline = catch_errors cache oss2swift swauth proxy-server

    To support Multipart Upload::

        [pipeline:main]
        pipeline = catch_errors cache oss2swift swauth slo proxy-server


If you use keystone:

    Was::

        [pipeline:main]
        pipeline = catch_errors cache authtoken keystone proxy-server

    Change To::

        [pipeline:main]
        pipeline = catch_errors cache oss2swift osstoken authtoken keystoneauth proxy-server

    To support Multipart Upload::

        [pipeline:main]
        pipeline = catch_errors cache oss2swift osstoken authtoken keystoneauth slo proxy-server

Note:
 * The authtoken filter requires the keystonemiddleware package.
 * oss2swift explicitly checks that keystoneauth is in the pipeline.  You must use this name
   in the pipeline statement and in [filter:keystoneauth] section header.

3) Add to your proxy-server.conf the section for the oss2swift WSGI filter::

    [filter:oss2swift]
    use = egg:oss2swift#oss2swift

You also need to add the following if you use keystone (adjust port, host, protocol configurations for your environment):

    [filter:osstoken]
    use = egg:oss2swift#osstoken
    auth_uri = http://127.0.0.1:35357/
    passwd=YourPassword

You also need to add the following if you use swauth :

    [filter:swauth]
    use = egg:swauth#swauth
    oss_support = on

4) oss2swift config options:

 You can find a proxy config example in `oss2swift/etc/proxy-server.conf-sample`.

    # Swift has no concept of the OSS's resource owner; the resources
    # (i.e. containers and objects) created via the Swift API have no owner
    # information. This option specifies how the oss2swift middleware handles them
    # with the OSS API.  If this option is 'false', such kinds of resources will be
    # invisible and no users can access them with the OSS API.  If set to 'true',
    # the resource without owner is belong to everyone and everyone can access it
    # with the OSS API.  If you care about OSS compatibility, set 'false' here.  This
    # option makes sense only when the oss_acl option is set to 'true' and your
    # Swift cluster has the resources created via the Swift API.
    allow_no_owner = false

    # Set a region name of your Swift cluster.  Note that oss2swift doesn't choose a
    # region of the newly created bucket actually.  This value is used only for the
    # GET Bucket location API.
    location = US

    # Set the default maximum number of objects returned in the GET Bucket
    # response.
    max_bucket_listing = 1000

    # Set the maximum number of objects we can delete with the Multi-Object Delete
    # operation.
    max_multi_delete_objects = 1000

    # If set to 'true', oss2swift uses its own metadata for ACL
    # (e.g. X-Container-Sysmeta-oss2swift-Acl) to achieve the best OSS compatibility.
    # If set to 'false', oss2swift tries to use Swift ACL (e.g. X-Container-Read)
    # instead of OSS ACL as far as possible.  If you want to keep backward
    # compatibility with oss2swift 1.7 or earlier, set false here
    # If set to 'false' after set to 'true' and put some container/object,
    # all users will be able to access container/object.
    # Note that oss_acl doesn't keep the acl consistency between OSS API and Swift
    # API. (e.g. when set ossacl to true and PUT acl, we won't get the acl
    # information via Swift API at all and the acl won't be applied against to
    # Swift API even if it is for a bucket currently supported.)
    # Note that oss_acl currently supports only keystone and tempauth.
    # DON'T USE THIS for production before enough testing for your use cases.
    # This stuff is still under development and it might cause something
    # you don't expect.
    oss_acl = false

    # Specify a host name of your Swift cluster.  This enables virtual-hosted style
    # requests.
    storage_domain =
