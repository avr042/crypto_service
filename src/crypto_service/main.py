from crypto_service.demo_environment import (
    create_demo_environment,
    print_demo_summary,
)


def main():
    demo_environment = create_demo_environment(
        reset_storage=True,
        issue_entity_certificates=False,
    )

    print_demo_summary(demo_environment)


if __name__ == "__main__":
    main()