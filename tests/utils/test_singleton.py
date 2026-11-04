from anonymia.utils.singleton import Singleton


def test_une_seule_instance_par_classe():
    class Config(metaclass=Singleton):
        def __init__(self):
            self.compteur = 0

    a, b = Config(), Config()
    a.compteur += 1

    assert a is b
    assert b.compteur == 1


def test_deux_classes_ont_chacune_leur_instance():
    class A(metaclass=Singleton):
        pass

    class B(metaclass=Singleton):
        pass

    assert A() is not B()
    assert A() is A()