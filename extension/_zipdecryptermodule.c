#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>


// Must be intialized on module init
static uint32_t CRC_TABLE [256] = {0};

static void 
InitCRCTable() {
    uint32_t poly = 0xedb88320;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; ++j) {
            if (crc & 0x1) {
                crc = ((crc >> 1) & 0x7FFFFFFF) ^ poly;
            }
            else {
                crc = ((crc >> 1) & 0x7FFFFFFF);
            }
        }
        CRC_TABLE[i] = crc;
    }
}

static uint32_t
CRC32(uint8_t ch, uint32_t crc) {
    return ((crc >> 8) & 0xffffff) ^ CRC_TABLE[(crc ^ ch) & 0xff];
}

typedef struct {
    PyObject_HEAD
    uint32_t key0;
    uint32_t key1;
    uint32_t key2;
} StandardZipDecrypterObject;

static void 
UpdateKeys(StandardZipDecrypterObject *decrypter, uint8_t c) {
    decrypter->key0 = CRC32(c, decrypter->key0);
    decrypter->key1 = (decrypter->key1 + (decrypter->key0 & 255)) & 4294967295;
    decrypter->key1 = (decrypter->key1 * 134775813 + 1) & 4294967295;
    decrypter->key2 = CRC32((decrypter->key1 >> 24) & 255, decrypter->key2);
}

static int
StandardZipDecrypter_init(StandardZipDecrypterObject *self, PyObject *args, PyObject *kwds) {
    const uint8_t *pwd = NULL;
    Py_ssize_t pwd_len = -1;

    if (!PyArg_ParseTuple(args, "y#", &pwd, &pwd_len)) {
        return -1;
    }
    
    self->key0 = 305419896;
    self->key1 = 591751049;
    self->key2 = 878082192;

    for (uint32_t i = 0; i < pwd_len; ++i) {
        UpdateKeys(self, pwd[i]);
    }
    return 0;
}

static PyObject *
StandardZipDecrypter_call(StandardZipDecrypterObject *self, PyObject *args, PyObject *kwds) {
    const PyBytesObject* input;

    if (!PyArg_ParseTuple(args, "S", &input)) {
        return NULL;
    }
    
    Py_ssize_t len = PyBytes_GET_SIZE(input);
    // Return from here because malloc(0) is undefined
    if (len == 0) {
        return PyBytes_FromStringAndSize("", 0);
    }
    
    const uint8_t* buffer = PyBytes_AS_STRING(input);

    uint8_t *output = malloc(len * sizeof(uint8_t));
    if (output == NULL) {
        return PyErr_NoMemory();
    }
    
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t c = buffer[i];
        uint32_t k = self->key2 | 2;
        c = c ^ (((k * (k^1)) >> 8) & 255);
        UpdateKeys(self, c);
        output[i] = c;
    }
    PyBytesObject *ret = PyBytes_FromStringAndSize(output, len);
    // Free allocated memory because it has been already copied to bytes object
    free(output);
    return ret;
}

static PyTypeObject StandardZipDecrypterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "zipdecrypter.StandardZipDecrypter",
    .tp_doc = "Zip Standard 2.0 Encrypted files decrypter",
    .tp_basicsize = sizeof(StandardZipDecrypterObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc) StandardZipDecrypter_init,
    .tp_call = (ternaryfunc) StandardZipDecrypter_call
};

static PyModuleDef zipdecryptermodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_zipdecrypter",
    .m_size = -1
};

PyMODINIT_FUNC
PyInit__zipdecrypter() {
    PyObject *m;
    if (PyType_Ready(&StandardZipDecrypterType) < 0) {
        return NULL;
    }

    m = PyModule_Create(&zipdecryptermodule);
    if (m == NULL) {
        return NULL;
    }

    if (PyModule_AddObject(m, "StandardZipDecrypter", (PyObject *) &StandardZipDecrypterType) != 0) {
        Py_DECREF(m);
        return NULL;
    }

    InitCRCTable();
    return m;
}
