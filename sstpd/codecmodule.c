#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdbool.h>

/* RFC 1662 
 * C.2. 16-bit FCS Computation Method
 * https://tools.ietf.org/html/rfc1662#appendix-C.2
 */

/*
 * u16 represents an unsigned 16-bit number.  Adjust the typedef for
 * your hardware.
 */
typedef unsigned short u16;

/*
 * FCS lookup table as calculated by the table generator.
 */
static u16 fcstab[256] = {
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

#define PPPINITFCS16     0xffff  /* Initial FCS value */
#define PPPGOODFCS16     0xf0b8  /* Good final FCS value */

#define FLAG_SEQUENCE    0x7e
#define CONTROL_ESCAPE   0x7d

#define MAX_FRAME_SIZE   2048

static inline void
escape_to(unsigned char byte, unsigned char* out, Py_ssize_t* pos)
{
    if (byte < 0x20 || byte == FLAG_SEQUENCE || byte == CONTROL_ESCAPE) {
        out[(*pos)++] = CONTROL_ESCAPE;
        out[(*pos)++] = byte ^ 0x20;
    }
    else {
        out[(*pos)++] = byte;
    }
}

static PyObject *
codec_escape(PyObject *self, PyObject *args)
{
    const unsigned char* data;
    Py_buffer buf_in;
    unsigned char* buffer;
    Py_ssize_t pos = 0;
    u16 fcs = PPPINITFCS16;
    int i;

    if (!PyArg_ParseTuple(args, "y*", &buf_in))
        return NULL;
    buffer = malloc(sizeof(char[(buf_in.len + 2) * 2 + 2]));
    if (!buffer)
        return PyErr_NoMemory();

    buffer[pos++] = FLAG_SEQUENCE;

    data = (unsigned char*) buf_in.buf;
    for (i=0; i<buf_in.len; ++i) {
        fcs = (fcs >> 8) ^ fcstab[(fcs ^ data[i]) & 0xff];
        escape_to(data[i], buffer, &pos);
    }
    PyBuffer_Release(&buf_in);

    fcs ^= 0xffff;
    escape_to(fcs & 0x00ff, buffer, &pos);
    escape_to(fcs >> 8, buffer, &pos);

    buffer[pos++] = FLAG_SEQUENCE;

    PyObject* result = Py_BuildValue("y#", buffer, pos);
    free(buffer);
    return result;
}


typedef struct {
    PyObject_HEAD
    char* frame_buf;
    Py_ssize_t frame_buf_pos;
    bool escaped;
} PppDecoder;


static PyObject *
PppDecoder_unescape(PppDecoder *self, PyObject *args)
{
    Py_buffer buf_in;
    const char* data; /* escaped data */
    PyObject* frames;
    int i;

    if (!PyArg_ParseTuple(args, "y*", &buf_in))
        return NULL;

    frames = PyList_New(0);
    if (!frames) {
        PyBuffer_Release(&buf_in);
        return NULL;
    }

    data = (char*) buf_in.buf;
    for (i=0; i<buf_in.len; ++i) {
        if (self->escaped) {
            self->escaped = false;
            self->frame_buf[self->frame_buf_pos++] = data[i] ^ 0x20;
        }
        else if (data[i] == CONTROL_ESCAPE) {
            self->escaped = true;
        }
        else if (data[i] == FLAG_SEQUENCE) {
            if (self->frame_buf_pos > 4) {
                /* Ignore 2-bytes FCS field */
                PyObject* frame = Py_BuildValue("y#",
                        self->frame_buf, self->frame_buf_pos - 2);
                if (PyList_Append(frames, frame) == -1) {
                    if (frame) Py_DECREF(frame);
                    self->frame_buf_pos = 0;
                    PyBuffer_Release(&buf_in);
                    return NULL;
                }
                Py_DECREF(frame);
            }
            self->frame_buf_pos = 0;
        }
        else if (self->frame_buf_pos < MAX_FRAME_SIZE) {
            self->frame_buf[self->frame_buf_pos++] = data[i];
        }
    }
    PyBuffer_Release(&buf_in);

    PyObject* result = Py_BuildValue("N", frames);
    return result;
}

static void
PppDecoder_dealloc(PppDecoder* self) {
    free(self->frame_buf);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
PppDecoder_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PppDecoder *self;
    self = (PppDecoder *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->frame_buf = malloc(sizeof(char[MAX_FRAME_SIZE]));
        if (!self->frame_buf) {
            Py_DECREF(self);
            return PyErr_NoMemory();
        }
        self->frame_buf_pos = 0;
        self->escaped = false;
    }
    return (PyObject *)self;
}

static PyMethodDef PppDecoder_methods[] = {
    {"unescape", (PyCFunction) PppDecoder_unescape, METH_VARARGS,
     "Unescape PPP frame stream, return a list of unescaped frame."
    },
    {NULL}  /* Sentinel */
};


static PyTypeObject codec_PppDecoderType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "codec.PppDecoder",               /* tp_name */
    sizeof(PppDecoder),               /* tp_basicsize */
    0,                                /* tp_itemsize */
    (destructor)PppDecoder_dealloc,   /* tp_dealloc */
    0,                                /* tp_print */
    0,                                /* tp_getattr */
    0,                                /* tp_setattr */
    0,                                /* tp_reserved */
    0,                                /* tp_repr */
    0,                                /* tp_as_number */
    0,                                /* tp_as_sequence */
    0,                                /* tp_as_mapping */
    0,                                /* tp_hash  */
    0,                                /* tp_call */
    0,                                /* tp_str */
    0,                                /* tp_getattro */
    0,                                /* tp_setattro */
    0,                                /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,               /* tp_flags */
    "PPP Decoder",                    /* tp_doc */
    0,                                /* tp_traverse */
    0,                                /* tp_clear */
    0,                                /* tp_richcompare */
    0,                                /* tp_weaklistoffset */
    0,                                /* tp_iter */
    0,                                /* tp_iternext */
    PppDecoder_methods,               /* tp_methods */
    0,                                /* tp_members */
    0,                                /* tp_getset */
    0,                                /* tp_base */
    0,                                /* tp_dict */
    0,                                /* tp_descr_get */
    0,                                /* tp_descr_set */
    0,                                /* tp_dictoffset */
    0,                                /* tp_init */
    0,                                /* tp_alloc */
    PppDecoder_new,                   /* tp_new */
};


static PyMethodDef CodecMethods[] = {
    {"escape", codec_escape, METH_VARARGS,
     "Escape a PPP frame ending with correct FCS code."},
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef codecmodule = {
    PyModuleDef_HEAD_INIT,
    "codec", /* name of module */
    NULL,    /* module documentation */
    -1,      /* keep state in global variables */
    CodecMethods
};

PyMODINIT_FUNC
PyInit_codec(void)
{
    PyObject* m;

    if (PyType_Ready(&codec_PppDecoderType) < 0)
        return NULL;

    m = PyModule_Create(&codecmodule);
    if (m == NULL)
        return NULL;
     Py_INCREF(&codec_PppDecoderType);
     PyModule_AddObject(m, "PppDecoder", (PyObject *) &codec_PppDecoderType);
     return m;
}

